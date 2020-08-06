local require = require
local cjson = require("cjson")
local cjson_s = require("cjson.safe")
local http = require("resty.http")
local r_session = require("resty.session")
local openidc = require("resty.openidc")
local string = string
local ipairs = ipairs
local pairs = pairs
local type = type
local ngx = ngx
local b64 = ngx.encode_base64
local unb64 = ngx.decode_base64

local log = ngx.log
local DEBUG = ngx.DEBUG
local ERROR = ngx.ERR
local WARN = ngx.WARN

local keycloak_caches = {
    "keycloak_config",
    "keycloak_discovery"
    -- add any other caches we use here
    -- this is used by keycloak.invalidate_caches()
}

local keycloak_realm_discovery_endpoints = {
    openid = ".well-known/openid-configuration",
    uma2   = ".well-known/uma2-configuration"
}

-- keycloak_openidc_defaults -- populated at the bottom of private functions

local keycloak = {
    _VERSION = "0.0.1"
}

-- this hash maps HTTP method to Keycloak scope
local keycloak_scope_map = {
    GET     = "view",
    HEAD    = "view",
    OPTIONS = "view",
    DELETE  = "write",
    PATCH   = "write",
    POST    = "write",
    PUT     = "write",
    CONNECT = "debug",
    TRACE   = "debug"
}

-- merge tables. Table "one" has priority
-- eg. keycloak_merge(config, defaults)
local function keycloak_merge(one, two)
    local one = one or {}
    local two = two or {}
    for k, v in pairs(one) do two[k] = v end

    return two
end

-- convert numbered table into a set
-- https://stackoverflow.com/a/656232
local function keycloak_table_to_set(list)
    local set = {}
    for _,l in ipairs(list) do set[l] = true end
    return set
end

-- find a value in a table
-- https://stackoverflow.com/a/664557
local function keycloak_table_find(f,subject)
    for _, v in ipairs(subject) do
        if f == v then
            return v
        end
    end
    return nil
end

local function keycloak_load_config(config_path)
    config_path = config_path or ngx.config.prefix() .. "/conf/keycloak.json"

    local file, err = io.open(config_path, "rb")
    if file == nil then
        ngx.status = 500
        log(ERROR, "Error loading keycloak json config: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local data_json = file:read("*a")
    file:close()

    local json = cjson.decode(data_json)
    return json
end

-- Returns the keycloak.json data as a Lua table
-- either from cache or by loading from disk
local function keycloak_config()
    -- TODO: cache keycloak.json
    local config = keycloak_load_config()
    return config
end

local function keycloak_realm_url()
    local config = keycloak_config()
    local auth_server_url = keycloak_config()["auth-server-url"]
    -- make sure the auth server url ends in /
    if string.sub(auth_server_url, -1) ~= '/' then
        auth_server_url = auth_server_url..'/'
    end
    return auth_server_url .. "realms/".. keycloak_config()["realm"]
end

local function keycloak_discovery_url(endpoint)
    local endpoint = endpoint or openid
    -- TODO: check that we have a configured endpoint url
    return keycloak_realm_url()  .."/".. keycloak_realm_discovery_endpoints["openid"]
end

-- This function is copied from resty.openidc
-- set value in server-wide cache if available
local function keycloak_cache_set(type, key, value, exp)
    local dict = ngx.shared[type]
    if dict and (exp > 0) then
        local success, err, forcible = dict:set(key, value, exp)
        log(DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
    end
end

-- This function is copied from resty.openidc
-- retrieve value from server-wide cache if available
local function keycloak_cache_get(type, key)
    local dict = ngx.shared[type]
    local value
    if dict then
        value = dict:get(key)
        if value then log(DEBUG, "cache hit: type=", type, " key=", key) end
    end
    return value
end

-- This function is copied from resty.openidc
-- invalidate values of server-wide cache
local function keycloak_cache_invalidate(type)
    local dict = ngx.shared[type]
    if dict then
        log(DEBUG, "flushing cache for " .. type)
        dict.flush_all(dict)
        local nbr = dict.flush_expired(dict)
    end
end

local function keycloak_discovery(endpoint_type)
    local discovery, err = keycloak.get_discovery_doc(endpoint_type)

    if err then
        ngx.status = 500
        log(ERROR, "Error getting keycloak discovery: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    else
        return discovery, nil
    end
end

local function keycloak_scope_for_method(method)
    local scope = "extended" -- this scope is returned for unknown HTTP methods (eg. WebDAV)
    if keycloak_scope_map[method] ~= nil then
        scope = keycloak_scope_map[method]
    end

    return scope
end

-- this function is adapted from openidc.call_token_endpoint()
local function keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)
    local endpoint_type = endpoint_type or "openid"
    local endpoint_name = endpoint_name or "token_endpoint"
    local headers = headers or {}
    local body = body or {}
    local params = params or {}
    local method = method or "POST"

    local discovery = keycloak_discovery(endpoint_type)
    local config = keycloak_config()
    local httpc = http.new()

    local params_string = ''

    for i,param in ipairs(params) do
        params_string = '/'..param
    end

    -- TODO: check that we have an endpoint for this
    local endpoint_url = discovery[endpoint_name]..params_string

    -- make sure form content type is set for POST method
    if method == "POST" then
        if headers["Content-Type"] == nil then
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        end

        if body.client_id == nil then
            body.client_id = config.resource
        end

        if body.client_secret == nil then
            body.client_secret = config.credentials.secret
        end
    end

    -- TODO: timeouts
    -- TODO: proxy

    local httpc_params = {
        method = method,
        body = ngx.encode_args(body),
        headers = headers,
        ssl_verify = true,
        keepalive = false
    }

    -- log(ERROR, "DEBUG: keycloak_call_endpoint() endpoint_url: "..endpoint_url)

    local res, err = httpc:request_uri(endpoint_url, httpc_params)

    if err then
        ngx.status = 500
        log(ERROR, "Error calling endpoint "..endpoint_name..": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: check for json decode errors
    return cjson_s.decode(res.body), err
end

local function keycloak_get_decision(access_token, resource_id)
    local endpoint_name = "token_endpoint"
    local endpoint_type = "uma2"
    local config = keycloak_config()
    -- TODO: error if access_token nil
    local headers = {
        ["Authorization"] = "Bearer " .. access_token
    }

    local body = {
        grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket",
        audience = config.resource,
        permission = resource_id,
        response_mode = "decision"
    }

    local res, err = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body)
    return res, err
end

local function keycloak_get_resource_set()
    local endpoint_type = "uma2"
    local endpoint_name = "resource_registration_endpoint"
    local headers = { Authorization = "Bearer " .. keycloak.service_account_token() }
    local body = {}
    local method = "GET"
    local params = {}
    local resource_set,err = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    return resource_set,err
end

local function keycloak_resource_set()
    -- TODO: fetch from cache
    local resource_set,err = keycloak_get_resource_set()
    if err then
        ngx.status = 500
        log(ERROR, "Error getting ressource set: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    else
        return resource_set
    end
end

local function keycloak_get_resource(resource_id)
    local endpoint_type = "uma2"
    local endpoint_name = "resource_registration_endpoint"
    local headers = { Authorization = "Bearer " .. keycloak.service_account_token() }
    local body = {}
    local params = { resource_id }
    local method = "GET"
    local resource,err = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    return resource,err
end

local function keycloak_resource(resource_id)
    -- no cache here because this is only called by keycloak_get_resources(),
    -- which has its own cache for the full hash
    local resource,err = keycloak_get_resource(resource_id)
    if err then
        ngx.status = 500
        log(ERROR, "Error getting ressource "..resource_id..": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    else
        return resource
    end
end

local function keycloak_get_resources()
    local resource_set = keycloak_resource_set()
    local resources = {}

    for k,resource_id in ipairs(resource_set) do
        -- log(ERROR, "DEBUG: calling keycloak_get_resource("..resource_id..")")
        resources[resource_id] = keycloak_get_resource(resource_id)
    end

    return resources
end

local function keycloak_resources()
    -- TODO: cache

    local resources = keycloak_get_resources()
    return resources
end

local keycloak_openidc_defaults = {
    redirect_uri  = "/callback",
    discovery     = keycloak_discovery_url("openid"),
    client_id     = keycloak_config()["resource"],
    client_secret = keycloak_config()["credentials"]["secret"]
}

local function keycloak_openidc_opts(openidc_opts)
    local openidc_opts = openidc_opts or {}
    return keycloak_merge(openidc_opts, keycloak_openidc_defaults)
end

-- return the match depth or nil if not found
local function keycloak_uri_path_match(subject, test)
    if subject == test then
        return string.len(test)
    end

    if test == '/' then
        return 1
    end

    local s,e = string.find(subject,test)
    local testlen = string.len(test)
    if (s == 1) and (e == testlen) and (string.sub(test,-1) == '/') then
        -- match depth is the whole policy uri and last character of policy uri is slash
        -- matches directory in policy to a directory path of the request path
        return e
    end

    return nil
end

local function keycloak_scopes_to_lookup_table(scope_hash)
    local lookup_table = {}
    for i,scope in ipairs(scope_hash) do
        lookup_table[scope.name] = true
    end

    return lookup_table
end

-- return the resource_id for the deepest match of uris for the given uri
-- returns nil if none found
local function keycloak_resourceid_for_request(request_uri,request_method)
    local request_uri = request_uri or ngx.var.request_uri
    local request_method = request_method or ngx.req.get_method()

    local keycloak_scope = keycloak_scope_for_method(ngx.req.get_method())
    local resources = keycloak_resources()

    -- TODO: log debug
    log(ERROR, "DEBUG: request_method: "..request_method.." keycloak_scope:"..keycloak_scope.." resource count: "..#resources)

    -- initialize "best match"
    local found_depth = 0
    local found = nil -- this will be replaced by the ID of the closest uri match

    for resource_id,resource in pairs(resources) do
        -- TODO: log debug
        log(ERROR, "DEBUG: Trying resource: \""..resource.name.."\"")

        local next = next -- scope searching speed hack
        local resource_scopes = keycloak_scopes_to_lookup_table(resource.resource_scopes)

        local resource_scopes_empty = false
        if next(resource_scopes) == nil then
            -- TODO: log debug
            log(ERROR, "DEBUG: Resource: \""..resource.name.."\": scopes empty.")
            resource_scopes_empty = true
        end

        local resource_scope_matches = resource_scopes[keycloak_scope] or false

        if resource_scope_matches then
            log(ERROR, "DEBUG: Resource: \""..resource.name.."\": found matching scope.")
            resource_scopes_empty = true
        else
            log(ERROR, "DEBUG: Resource: \""..resource.name.."\": no matching scopes.")
            resource_scopes_empty = true
        end

        -- only test the resource URIs if the method matches the resource scope
        -- or the resource doesn't list any associated scopes
        if resource_scopes_empty or resource_scope_matches then
            -- TODO: log debug
            log(ERROR, "DEBUG: Testing resource: \""..resource.name.."\": matching resource scope or scopes empty.")
            for i,uri in ipairs(resource.uris) do
                local match_depth = keycloak_uri_path_match(request_uri,uri) or 0
                if match_depth > found_depth then
                    found_depth = match_depth
                    found = resource_id
                end
            end
        else
            -- TODO: log debug
            log(ERROR, "DEBUG: Skipping resource: \""..resource.name.."\": no matching resource scope and scopes not empty.")
        end
    end
    return found,found_depth
end

-----------
-- Public Functions

function keycloak.get_discovery_doc(endpoint_type)
    local endpoint_type = endpoint_type or "openid"

    local httpc = http.new()
    local discovery_url = keycloak_realm_url().."/"..keycloak_realm_discovery_endpoints[endpoint_type]

    local httpc_params = {
        method = "GET",
        keepalive = false
    }

    local res,err = httpc:request_uri(discovery_url, httpc_params)
    if err then
        ngx.status = 500
        log(ERROR, "Error fetching "..endpoint_type.." discovery at "..discovery_url.." : "..err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: check for json decode errors
    return cjson_s.decode(res.body), err
end

function keycloak.service_account_token()
    local endpoint_name = "token_endpoint"
    local endpoint_type = "openid"
    local config = keycloak_config()

    local body = {
        grant_type = "client_credentials"
    }

    local res, err = keycloak_call_endpoint(endpoint_type, endpoint_name, {}, body)

    return res.access_token
end

function keycloak.dumpTable(table, depth)
    local depth = depth or 0
    for k,v in pairs(table) do
        if (type(v) == "table") then
            ngx.say(string.rep("  ", depth)..k..":")
            keycloak.dumpTable(v, depth+1)
        else
            ngx.say(string.rep("  ", depth)..k..": ",v)
        end
    end
end

function keycloak.decision(access_token, resource_id)
    local decision
    local err

    -- TODO: cache
    decision,err = keycloak_get_decision(access_token, resource_id)
    -- TODO: error out here?
    return decision,err
end

function keycloak.authenticate(openidc_opts)
    local opts = keycloak_openidc_opts(openidc_opts)
    local res, err, target_url, session = openidc.authenticate(opts)

    return res, err, target_url, session
end

function keycloak.session_token(openidc_opts, session_opts)
    local opts = keycloak_openidc_opts(openidc_opts)
    return openidc.access_token(opts, session_opts)
end

-- invalidate all server-wide caches
function keycloak.invalidate_caches()
    for i,cache in ipairs(keycloak_caches) do
        keycloak_cache_invalidate(cache)
    end
end

keycloak.__index = keycloak
return keycloak
