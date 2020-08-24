local require   = require
local cjson     = require("cjson")
local cjson_s   = require("cjson.safe")
local http      = require("resty.http")
local r_session = require("resty.session")
local openidc   = require("resty.openidc")
local string    = string
local ipairs    = ipairs
local pairs     = pairs
local type      = type
local ngx       = ngx

-- localize Nginx logging
local log   = ngx.log
local DEBUG = ngx.DEBUG
local ERROR = ngx.ERR
local WARN  = ngx.WARN

-- initialize the resty-keycloak instance
-- TODO: resolve all of the different ways the config file (keycloak.json) path could be provided to the extension. The config data needs to be loaded early.
local keycloak = {
    _VERSION = "0.0.1"
}

-- list of all caches used in this code
-- this is used by keycloak.invalidate_caches()
local keycloak_caches = {
    "keycloak_config",
    "keycloak_discovery"
    -- add any other caches we use here
}

-- Keycloak URIs for service discovery
local keycloak_realm_discovery_endpoints = {
    openid = ".well-known/openid-configuration",
    uma2   = ".well-known/uma2-configuration"
}

-- keycloak_openidc_defaults -- populated above keycloak_openidc_opts()

-- this hash maps HTTP method to Keycloak scope
-- these scopes can be added to resources in Keycloak to limit authz rules to HTTP methods
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

-- timeouts used for httpc client calls (in milliseconds)
local keycloak_http_timeouts = {
    connect_timeout = 10000,
    send_timeout    = 5000,
    read_timeout    = 5000
}

-----------
-- Utility Functions

-- merge tables. Table "one" has priority
-- eg. keycloak_merge(config, defaults)
local function keycloak_merge(one, two)
    assert(type(one) == "table")
    assert(type(two) == "table")

    for k, v in pairs(one) do two[k] = v end

    return two
end

-----------
-- Private Functions

-- loads the Keycloak-generated keycloak.json from disk
local function keycloak_load_config(config_path)
    -- TODO: remove keycloak.json file support?
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
    -- TODO: check for JSON decode error
    return json
end

-- Returns the Keycloak-generated keycloak.json data as a Lua table
-- this file is generated in Keycloak, downloadable in the client "Installation" tab
-- "Keycloak OIDC JSON" format option
local function keycloak_config(config_path)
    -- TODO all Keycloak config may come from ENV settings

    -- TODO: cache keycloak.json
    local config = keycloak_load_config(config_path)
    return config
end

-- returns the base URL for the configured Keycloak realm
local function keycloak_realm_url()
    local config          = keycloak_config()
    assert(type(config)   == "table")

    local auth_server_url = config["auth-server-url"]
    -- make sure the auth server url ends in /
    if string.sub(auth_server_url, -1) ~= '/' then
        auth_server_url = auth_server_url .. '/'
    end

    return auth_server_url .. "realms/" .. keycloak_config()["realm"]
end

-- returns a Keycloak URL for a given endpoint type
local function keycloak_discovery_url(endpoint_type)
    local endpoint_type = endpoint_type or "openid"

    -- make sure endpoint is valid
    if keycloak_realm_discovery_endpoints[endpoint_type] == nil then
        ngx.status = 500
        log(ERROR, "Unknown Keycloak realm discovery endpoint type \"" .. endpoint_type .. "\"")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return keycloak_realm_url() .. "/" .. keycloak_realm_discovery_endpoints["openid"]
end

-- This function is copied from resty.openidc
-- set value in server-wide cache if available
local function keycloak_cache_set(type, key, value, exp)
    -- TODO: redis integration
    local dict = ngx.shared[type]
    if dict and (exp > 0) then
        local success, err, forcible = dict:set(key, value, exp)
        log(DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
    end
end

-- This function is copied from resty.openidc
-- retrieve value from server-wide cache if available
local function keycloak_cache_get(type, key)
    -- TODO: redis integration
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
    -- TODO: redis integration
    local dict = ngx.shared[type]
    if dict then
        log(DEBUG, "flushing cache for " .. type)
        dict.flush_all(dict)
        local nbr = dict.flush_expired(dict)
    end
end

-- fetch the OpenID discovery document for the given endpoint type
local function keycloak_get_discovery_doc(endpoint_type)
    assert(type(endpoint_type) == "string")

    local httpc         = http.new()
    local discovery_url = keycloak_realm_url() .. "/" .. keycloak_realm_discovery_endpoints[endpoint_type]

    local httpc_params = {
        method    = "GET",
        keepalive = false
    }

    -- configure httpc timeouts (connect_timeout, send_timeout, read_timeout)
    httpc.set_timeouts(
        keycloak_http_timeouts["connect_timeout"],
        keycloak_http_timeouts["send_timeout"],
        keycloak_http_timeouts["read_timeout"]
    )

    local res,err = httpc:request_uri(discovery_url, httpc_params)
    if err then
        ngx.status = 500
        log(ERROR, "Error fetching " .. endpoint_type .. " discovery at " .. discovery_url .. " : " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: check for json decode errors
    return cjson_s.decode(res.body), err
end

local function keycloak_discovery(endpoint_type)
    local endpoint_type = endpoint_type or "openid"

    -- if endpoint_type is not a key in keycloak_realm_discovery_endpoints,
    -- it's invalid, abort.
    if keycloak_realm_discovery_endpoints[endpoint_type] == nil then
        ngx.status = 500
        log(ERROR, "Unknown Keycloak endpoint type \"" .. endpoint_type .. "\"")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: cache
    local discovery, err = keycloak_get_discovery_doc(endpoint_type)

    if err then
        ngx.status = 500
        log(ERROR, "Error getting keycloak discovery: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    else
        return discovery, nil
    end
end

-- converts HTTP method into Keycloak scope or "extended" if unknown
-- eg. GET => read
local function keycloak_scope_for_method(method)
    assert(type(method) == "string")

    local scope = "extended" -- this scope is returned for unknown HTTP methods (eg. WebDAV)

    -- if we have mapped the HTTP request method to a Keycloak scope, use that
    if keycloak_scope_map[method] ~= nil then
        scope = keycloak_scope_map[method]
    end

    return scope
end

--[[
    make an HTTP request to a Keycloak endpoint

    endpoint_type (string): from keycloak_realm_discovery_endpoints
    endpoint_name (string): the index in the discovery document data that will have the endpoint URL to call
    headers (table)       : HTTP headers to add to the Keycloak request (see Keycloak API documentation)
    body (table)          : body content for HTTP POST requests. Known requirements added if missing (see Keycloak API documentation)
    params (table)        : HTTP URL parameters (eg. ?foo=bar&baz=qux) (see Keycloak API documentation)
    method (string)       : HTTP request method (eg. GET or POST) (see Keycloak API documentation)

    returns the decoded JSON from the Keycloak response

    this function is adapted from openidc.call_token_endpoint()
--]]
local function keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)
    local endpoint_type = endpoint_type or "openid"
    local endpoint_name = endpoint_name or "token_endpoint"
    local headers       = headers or {}
    local body          = body or {}
    local params        = params or {}
    local method        = method or "POST"

    local discovery     = keycloak_discovery(endpoint_type)
    local config        = keycloak_config()
    local httpc         = http.new()

    -- build params string from table
    local params_string = ''
    for _,param in ipairs(params) do
        params_string = '/' .. param
    end

    -- abort if the discovery doc is missing endpoint_name
    if discovery[endpoint_name] == nil then
        ngx.status = 500
        log(ERROR, "Discovery document type \"" .. endpoint_type .. "\" missing enpoint name \"" .. endpoint_name .. "\"")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    local endpoint_url = discovery[endpoint_name] .. params_string

    -- ensure basic requirements are included for Keycloak enpoint POST requests
    if method == "POST" then
        -- make sure form content type is set for POST method
        if headers["Content-Type"] == nil then
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        end

        -- make sure client_id is set (resource server authentication)
        if body.client_id == nil then
            body.client_id = config.resource
        end

        -- make sure client secret is included (resource server authentication)
        if body.client_secret == nil then
            body.client_secret = config.credentials.secret
        end
    end

    -- configure httpc timeouts (connect_timeout, send_timeout, read_timeout)
    httpc.set_timeouts(
        keycloak_http_timeouts["connect_timeout"],
        keycloak_http_timeouts["send_timeout"],
        keycloak_http_timeouts["read_timeout"]
    )

    -- TODO: do we need to do anything with httpc proxy here for proxied servers?

    local httpc_params = {
        method     = method,
        body       = ngx.encode_args(body),
        headers    = headers,
        ssl_verify = true,
        keepalive  = false
    }

    local res, err = httpc:request_uri(endpoint_url, httpc_params)
    -- check for HTTP client errors
    if err then
        ngx.status = 500
        log(ERROR, "Error calling endpoint " .. endpoint_name .. ": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local decoded,decode_err = cjson_s.decode(res.body)
    -- check for json decode errors
    if decode_err then
        ngx.status = 500
        log(ERROR, "Error decoding JSON response from Keycloak \"" .. endpoint_name .. "\": " .. decode_err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return decoded
end

-- request an authorization decision from Keycloak
-- access_token (string) : access_token from session of logged-in user (eg. session.data.access_token)
-- resource_id (string)  : the ID (not the name!) of the Keycloak UMA2 resource
--
-- returns the raw response to the caller
local function keycloak_get_decision(access_token, resource_id)
    assert(type(access_token) == "string")
    assert(type(resource_id)  == "string")

    local endpoint_name = "token_endpoint"
    local endpoint_type = "uma2"

    local config        = keycloak_config()

    local headers = {
        ["Authorization"] = "Bearer " .. access_token
    }

    local body = {
        grant_type    = "urn:ietf:params:oauth:grant-type:uma-ticket",
        audience      = config.resource,
        permission    = resource_id,
        response_mode = "decision"
    }

    local res = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body)
    return res
end

local function keycloak_get_resource_set()
    local endpoint_type = "uma2"
    local endpoint_name = "resource_registration_endpoint"
    local headers       = { Authorization = "Bearer " .. keycloak.service_account_token() }
    local body          = {}
    local method        = "GET"
    local params        = {}
    local resource_set  = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    return resource_set
end

local function keycloak_resource_set()
    -- TODO: cache

    local resource_set = keycloak_get_resource_set()
    assert(type(resource_set) == "table")

    return resource_set
end

local function keycloak_get_resource(resource_id)
    local endpoint_type = "uma2"
    local endpoint_name = "resource_registration_endpoint"
    local headers       = { Authorization = "Bearer " .. keycloak.service_account_token() }
    local body          = {}
    local params        = { resource_id }
    local method        = "GET"
    local resource      = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    return resource
end

local function keycloak_get_resources()
    local resource_set = keycloak_resource_set()
    local resources    = {}

    for k,resource_id in ipairs(resource_set) do
        resources[resource_id] = keycloak_get_resource(resource_id)
    end

    return resources
end

local function keycloak_resources()
    -- TODO: cache

    local resources = keycloak_get_resources()

    return resources
end

-- this global has to be declared here; after all of the required functions are defined, and before keycloak_openidc_opts()
local keycloak_openidc_defaults = {
    redirect_uri  = "/callback",
    discovery     = keycloak_discovery_url("openid"),
    client_id     = keycloak_config()["resource"],
    client_secret = keycloak_config()["credentials"]["secret"]
}

-- generate the required opts table for resty.openidc calls
local function keycloak_openidc_opts(openidc_opts)
    local openidc_opts = openidc_opts or {}

    return keycloak_merge(openidc_opts, keycloak_openidc_defaults)
end

-- return the match depth or nil if not found
local function keycloak_uri_path_match(subject, test)
    local subject = subject or ""
    local test    = test    or ""

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
    assert(type(scope_hash) == "table")

    local lookup_table = {}
    for _,scope in ipairs(scope_hash) do
        lookup_table[scope.name] = true
    end

    return lookup_table
end

-- return the resource_id for the deepest match of uris for the given uri
-- returns nil if none found
local function keycloak_resourceid_for_request(request_uri,request_method)
    local request_uri    = request_uri or ngx.var.request_uri
    local request_method = request_method or ngx.req.get_method()

    local keycloak_scope = keycloak_scope_for_method(ngx.req.get_method())
    local resources      = keycloak_resources()

    log(DEBUG, "request_method: " .. request_method .. " keycloak_scope:" .. keycloak_scope .. " resource count: " .. #resources)

    -- initialize "best match"
    local found_depth = 0
    local found       = nil -- this will be replaced by the ID of the closest uri match

    for resource_id,resource in pairs(resources) do
        log(DEBUG, "Trying resource: \"" .. resource.name .. "\"")

        local next            = next -- scope searching speed hack
        local resource_scopes = keycloak_scopes_to_lookup_table(resource.resource_scopes)

        local resource_scopes_empty = false
        if next(resource_scopes) == nil then
            log(DEBUG, "Resource: \"" .. resource.name .. "\": scopes empty.")
            resource_scopes_empty = true
        end

        local resource_scope_matches = resource_scopes[keycloak_scope] or false

        if resource_scope_matches then
            log(DEBUG, "Resource: \"" .. resource.name .. "\": found matching scope.")
            resource_scopes_empty = true
        else
            log(DEBUG, "Resource: \"" .. resource.name .. "\": no matching scopes.")
            resource_scopes_empty = true
        end

        -- only test the resource URIs if the method matches the resource scope
        -- or the resource doesn't list any associated scopes
        if resource_scopes_empty or resource_scope_matches then
            log(DEBUG, "Testing resource: \"" .. resource.name .. "\": matching resource scope or scopes empty.")
            for _,uri in ipairs(resource.uris) do
                local match_depth = keycloak_uri_path_match(request_uri,uri) or 0
                if match_depth > found_depth then
                    found_depth = match_depth
                    found       = resource_id
                end
            end
        else
            log(DEBUG, "Skipping resource: \"" .. resource.name .. "\": no matching resource scope and scopes not empty.")
        end
    end
    return found,found_depth
end

-----------
-- Public Functions

function keycloak.service_account_token()
    local endpoint_name = "token_endpoint"
    local endpoint_type = "openid"
    local config        = keycloak_config()

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
            ngx.say(string.rep("  ", depth) .. k .. ":")
            keycloak.dumpTable(v, depth+1)
        else
            ngx.say(string.rep("  ", depth) .. k .. ": ",v)
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
    local openidc_opts = openidc_opts or {}

    local opts                          = keycloak_openidc_opts(openidc_opts)
    local res, err, target_url, session = openidc.authenticate(opts)

    return res, err, target_url, session
end

-- invalidate all server-wide caches
function keycloak.invalidate_caches()
    for _,cache in ipairs(keycloak_caches) do
        keycloak_cache_invalidate(cache)
    end
end

function keycloak.authorize(session_token)
    -- TODO: authorization may not be enabled for the resource
    -- catch empty access token
    if session_token == nil then
        ngx.status = 403
        log(ERROR, "Session token is nil: access forbidden.")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    log(DEBUG, "Matching URI with Keycloak resources")
    local resource_id = keycloak_resourceid_for_request()

    -- forbidden if no matching resources found
    if resource_id == nil then
        ngx.status = 403
        log(ERROR, "No matching resources: access forbidden.")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    log(DEBUG, "Matched resource ID: " .. resource_id)
    local decision,err = keycloak.decision(session_token,resource_id)
    -- catch decision internal error
    if err then
        ngx.status = 500
        log(ERROR, "Error fetching keycloak decision: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    -- catch decision unexpected return type
    if type(decision) ~= "table" then
        ngx.status = 500
        log(ERROR, "Unexpected Keycloak decision return data type: " .. type(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    -- catch authorization error (eg. not authorized)
    if decision.error ~= nil then
        ngx.status = 403
        log(ERROR, "Keycloak returned authorization error: " .. cjson_s.encode(decision))
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    -- catch unknown Keycloak response
    if decision.result ~= true then
        ngx.status = 500
        log(ERROR, "Unexpected Keycloak decision content: " .. cjson_s.encode(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    log(DEBUG, "Keycloak authorization successful.")
    -- authz successful
    return true
end

-----------
-- Bless keycloak table as object

keycloak.__index = keycloak
return keycloak
