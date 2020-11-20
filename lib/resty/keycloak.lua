local require   = require
local cjson     = require("cjson")
local cjson_s   = require("cjson.safe")
local http      = require("resty.http")
local r_session = require("resty.session")
local openidc   = require("resty.openidc")
local r_env     = require("resty.env")
-- local redis     = require("resty.redis")
local string    = string
local ipairs    = ipairs
local pairs     = pairs
local type      = type
local ngx       = ngx

-- initialize the resty-keycloak instance
local keycloak = {
    _VERSION = "0.0.1"
}

-- default configuration
local keycloak_default_config = {
    anonymous_policy_mode = "permissive", -- enforcing, permissive, disabled : enforcing requires anonymous_scope to be in the resource scopes
    anonymous_scope       = "read-public", -- keycloak scope to allow anonymous
    auth_server_url       = "http://localhost:8080/auth",
    client_id             = "nginx",
    client_secret         = "00000000-0000-0000-0000-000000000000",
    realm                 = "master",
}

-- list of all caches used in this code
-- this is used by keycloak.invalidate_caches()
local keycloak_caches = {
    "keycloak_config",
    "keycloak_discovery",
    "resource_set",
    -- add any other caches we use here
}

-- Keycloak URIs for service discovery
local keycloak_realm_discovery_endpoints = {
    openid = ".well-known/openid-configuration",
    uma2   = ".well-known/uma2-configuration",
}

-- keycloak_openidc_defaults -- populated above keycloak_openidc_opts()

-- this hash maps HTTP method to Keycloak scope
-- these scopes can be added to resources in Keycloak to limit authz rules to HTTP methods
local keycloak_scope_for_method = {
    GET     = "view",
    HEAD    = "view",
    OPTIONS = "view",
    DELETE  = "write",
    PATCH   = "write",
    POST    = "write",
    PUT     = "write",
    CONNECT = "debug",
    TRACE   = "debug",
}

-- timeouts used for httpc client calls (in milliseconds)
local keycloak_http_timeouts = {
    connect_timeout = 10000,
    send_timeout    = 5000,
    read_timeout    = 5000,
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

-- Merges tables one and two where one has non-default values
-- Table "one" has priority.
-- this is useful where there are multiple sources of config data all with default values set
local function keycloak_merge_config(one,two,defaults)
    assert(type(one)      == "table")
    assert(type(two)      == "table")
    assert(type(defaults) == "table")

    local newtable = two
    for k,v in pairs(one) do
        newtable[k] = (one[k] ~= defaults[k]) and one[k] or two[k]
    end

    return newtable
end

-- searches a table t for a value v
-- returns boolean
local function keycloak_table_has_value(t,v)
    for ti,tv in pairs(t) do
        if tv == v then return true end
    end
    return false
end

-----------
-- Private Functions


-- Returns KeyCloak client configuration as a Lua table.
-- Pulls in all values from defaults (keycloak_default_config)
-- Overrides default values with ENV values where they are not default
-- Overrides default + ENV with Nginx "set" values where they are not default
-- Nginx "set" values are the highest priority, so admins can avoid having sensitive data in ENV
local function keycloak_get_config()
    local env_table = {}
    local ngx_table = {}

    -- get ENV values based on default config keys
    -- eg. keycloak_default_config["foo"] will look for ENV["KEYCLOAK_FOO"]
    -- eg. keycloak_default_config["foo"] will look for nginx.var.keycloak_foo
    for k,v in pairs(keycloak_default_config) do
        local env_key_name = "KEYCLOAK_" .. string.upper(k)
        local set_key_name = "keycloak_" .. k
        env_table[k] = r_env.get(env_key_name) or keycloak_default_config[k]
        ngx_table[k] = ngx.var[set_key_name] or keycloak_default_config[k]
    end
    return keycloak_merge_config(ngx_table, env_table, keycloak_default_config)
end

-- returns the keycloak configuration from cache, or calls keycloak_get_config to calculate
local function keycloak_config()
    -- TODO: cache keycloak config
    local config = keycloak_get_config()
    return keycloak_merge(config,keycloak_default_config)
end

-- returns the base URL for the configured Keycloak realm
local function keycloak_realm_url()
    local config          = keycloak_config()
    assert(type(config)   == "table")

    local auth_server_url = config["auth_server_url"]
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
        ngx.log(ngx.ERR, "Unknown Keycloak realm discovery endpoint type \"" .. endpoint_type .. "\"")
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
        ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
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
        if value then ngx.log(ngx.DEBUG, "cache hit: type=", type, " key=", key) end
    end
    return value
end

-- This function is copied from resty.openidc
-- invalidate values of server-wide cache
local function keycloak_cache_invalidate(type)
    -- TODO: redis integration
    local dict = ngx.shared[type]
    if dict then
        ngx.log(ngx.DEBUG, "flushing cache for " .. type)
        dict.flush_all(dict)
        local nbr = dict.flush_expired(dict)
    end
end

-- fetch the OpenID discovery document for the given endpoint type
local function keycloak_get_discovery(endpoint_type)
    assert(type(endpoint_type) == "string")

    local httpc         = http.new()
    local discovery_url = keycloak_realm_url() .. "/" .. keycloak_realm_discovery_endpoints[endpoint_type]

    local httpc_params = {
        method    = "GET",
        keepalive = false
    }

    -- configure httpc timeouts (connect_timeout, send_timeout, read_timeout)
    httpc:set_timeouts(
        keycloak_http_timeouts["connect_timeout"],
        keycloak_http_timeouts["send_timeout"],
        keycloak_http_timeouts["read_timeout"]
    )

    local res,err = httpc:request_uri(discovery_url, httpc_params)

    -- check the HTTP response code from the discovery request
    if res.status ~= 200 then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error fetching " .. endpoint_type .. " discovery at " .. discovery_url .. " : " .. "code:" .. res.status .. " reason: " .. res.reason)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if err then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error fetching " .. endpoint_type .. " discovery at " .. discovery_url .. " : " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- check for json decode errors
    local discovery_decoded = cjson_s.decode(res.body)
    if discovery_decoded == nil then
        ngx.status = 500
        ngx.log(ngx.ERR, "Invalid JSON decoding " .. endpoint_type .. " discovery at " .. discovery_url)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return discovery_decoded
end

local function keycloak_discovery(endpoint_type)
    local endpoint_type = endpoint_type or "openid"

    -- if endpoint_type is not a key in keycloak_realm_discovery_endpoints,
    -- it's invalid, abort.
    if keycloak_realm_discovery_endpoints[endpoint_type] == nil then
        ngx.status = 500
        ngx.log(ngx.ERR, "Unknown Keycloak endpoint type \"" .. endpoint_type .. "\"")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: cache
    local discovery = keycloak_get_discovery(endpoint_type)

    return discovery
end

-- converts HTTP method into Keycloak scope or "extended" if unknown
-- eg. GET => read
local function method_scope_for_method(method)
    assert(type(method) == "string")

    local scope = "extended" -- this scope is returned for unknown HTTP methods (eg. WebDAV)

    -- if we have mapped the HTTP request method to a Keycloak scope, use that
    if keycloak_scope_for_method[method] ~= nil then
        scope = keycloak_scope_for_method[method]
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
        ngx.log(ngx.ERR, "Discovery document type \"" .. endpoint_type .. "\" missing enpoint name \"" .. endpoint_name .. "\"")
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
    httpc:set_timeouts(
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
    -- TODO: check response HTTP error code
    -- check for HTTP client errors
    if err then
        ngx.log(ngx.ERR, "Error calling endpoint " .. endpoint_name .. ": " .. err)
        return nil,err
    end

    local decoded = cjson_s.decode(res.body)
    -- check for json decode errors
    if decoded == nil then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error decoding JSON response from Keycloak \"" .. endpoint_name .. "\"")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return decoded,err
end

-- request an authorization decision from Keycloak
-- access_token (string) : access_token from session of logged-in user (eg. session.data.access_token)
-- resource_id (string)  : the ID (not the name!) of the Keycloak UMA2 resource
--
-- returns response body table and error string from KeyCloak
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

    -- TODO validate what happens here with permission denied. KC will return 403?
    local res,err = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body)

    -- TODO: handle err here or in wrapper?

    return res,err
end

local function keycloak_get_resource_set()
    local endpoint_type     = "uma2"
    local endpoint_name     = "resource_registration_endpoint"
    local headers           = { Authorization = "Bearer " .. keycloak.service_account_token() }
    local body              = {}
    local method            = "GET"
    local params            = {}
    local resource_set,err  = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    -- TODO: handle err

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
    local resource,err  = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body, params, method)

    -- TODO: handle err

    return resource
end

local function keycloak_resource(resource_id)
    assert(type(resource_id) == "string")

    -- TODO: cache
    local resource = keycloak_get_resource(resource_id)
    assert(type(resource) == "table")

    return resource
end

local function keycloak_get_resources()
    local resource_set = keycloak_resource_set()
    local resources    = {}
    local count        = 0

    for k,resource_id in ipairs(resource_set) do
        resources[resource_id] = keycloak_resource(resource_id)
        count = count +1
    end

    return resources,count
end

local function keycloak_resources()
    local resources,count = keycloak_get_resources()
    assert(type(resources) == "table")

    return resources,count
end

-- this global has to be declared here; after all of the required functions are defined, and before keycloak_openidc_opts()
local keycloak_openidc_defaults = {
    -- TODO: callback URI needs to be configurable
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

    -- check for simple exact match
    if subject == test then
        return string.len(test)
    end

    -- if the pattern has no wildcards, stop here
    if string.find(test, "[?*]") == nil then
        return nil
    end

    -- shortcut "whole site" glob
    if test == '/*' then
        return 1
    end

    -- wildcard match depth is the number of characters matched without wildcard expansion
    local test_depth = string.len(string.gsub(test,"[?*]",""))

    -- Convert globs to lua patterns
    -- ... escape all .
    test = string.gsub(test, "%.", "\\.")
    -- ... replace all ? with .
    test = string.gsub(test, "%?", '.')
    -- ... replace all * with .+
    test = string.gsub(test, "%*", ".+")

    -- get the beginning and end positions in the subject string that match the test
    local start_match, end_match = string.find(subject, test)
    -- it's only a match if it's the whole string (1 to length)
    if start_match == 1 and end_match == string.len(subject) then
        -- match successful, return the number of non-wildcard characters in the test as a "match quality rating"
        return test_depth
    else
        -- match failed
        return nil
    end
end

local function keycloak_request_method_to_scope(method)
    assert(type(method) == "string")

    local scope = "extended" -- this scope is returned for unknown HTTP methods (eg. WebDAV)

    -- if we have mapped the HTTP request method to a Keycloak scope, use that
    if keycloak_scope_for_method[method] ~= nil then
        scope = keycloak_scope_for_method[method]
    end

    return scope
end

local function keycloak_resource_scope_hash_to_lookup_table(scope_hash)
    assert(type(scope_hash) == "table")

    local lookup_table = {}
    for _,scope in ipairs(scope_hash) do
        lookup_table[scope.name] = true
    end

    return lookup_table
end

local function keycloak_resource_scopes_include_request_methods(resource_scopes)
    for _,scope in pairs(resource_scopes) do -- for each associated scope...
        -- check if this scope in the table of method scopes
        if keycloak_table_has_value(keycloak_scope_for_method,scope) ~= nil then
            return true
        end
    end
    return false
end

-- return the resource_id for the deepest match of uris for the given uri
-- returns nil if none found
local function keycloak_resourceid_for_request(request_uri,request_method)
    local request_uri               = request_uri or ngx.var.request_uri
    local request_method            = request_method or ngx.req.get_method()
    local request_method_scope      = keycloak_request_method_to_scope(request_method)
    local resources,resources_count = keycloak_resources()

    assert(type(resources) == "table")

    ngx.log(ngx.DEBUG, "request_uri:" .. request_uri .. " request_method:" .. request_method .. " method_scope:" .. request_method_scope .. " resource count:" .. resources_count)

    -- initialize "best match"
    local found_depth = 0
    local found       = nil -- this will be replaced by the ID of the closest uri match

    for resource_id,resource in pairs(resources) do
        ngx.log(ngx.DEBUG, "Trying resource: \"" .. resource.name .. "\"")

        local resource_scopes = keycloak_resource_scope_hash_to_lookup_table(resource.resource_scopes)
        -- search for any method scopes (scopes mapped to HTTP methods)
        -- if there are any associated method scopes, the request method must match
        local resource_has_method_scopes = keycloak_resource_scopes_include_request_methods(resource_scopes)

        local resource_scopes_include_request_method = false
        if resource_has_method_scopes then
            ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\" has method scopes.")
            -- check if the request scope is in the associated resource scopes
            if resource_scopes[request_method_scope] ~= nil then
                resource_scopes_include_request_method = true
                ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": found matching scope: " .. request_method_scope)
            else
                ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": no matching scopes.")
            end
        else
            ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\" no method scopes.")
        end

        -- only test the resource URIs if the request method matches the resource scope
        -- or the resource doesn't list any associated scopes
        if resource_scopes_include_request_method or (resource_has_method_scopes == false) then
            ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": passed scope check, testing " .. #resource.uris .. " resource URI patterns: " .. table.concat(resource.uris, ","))
            for _,uri in ipairs(resource.uris) do
                ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": testing pattern:" .. uri .. " against request:" .. request_uri)
                local match_depth = keycloak_uri_path_match(request_uri,uri) or 0
                if match_depth > 0 then
                    ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": URI pattern \"" .. uri .. "\" matches at depth " .. match_depth)
                    if match_depth > found_depth then
                        ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": URI pattern \"" .. uri .. "\" is deeper (" .. match_depth .. ") than previous match (" .. found_depth .. ")")
                        found_depth = match_depth
                        found       = resource_id
                    else
                        ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": URI pattern \"" .. uri .. "\" is shallower (" .. match_depth .. ") than previous match (" .. found_depth .. ")")
                    end
                else
                    ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": URI pattern \"" .. uri .. "\" does not match")
                end
            end
        else
            ngx.log(ngx.DEBUG, "Resource: \"" .. resource.name .. "\": skipping URI check: disqualified by method scope.")
        end
    end
    return found,found_depth
end

--[[
    fetch the service account token from Keycloak for the client application

    returns the SA access token as a string
--]]
local function keycloak_get_service_account_token()
    local endpoint_name = "token_endpoint"
    local endpoint_type = "openid"
    local config        = keycloak_config()

    local body = {
        grant_type = "client_credentials"
    }

    local res, err = keycloak_call_endpoint(endpoint_type, endpoint_name, {}, body)

    -- check for SA token error
    if err then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error calling endpoint " .. endpoint_name .. ": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- make sure the response has an access token
    if type(res.access_token) ~= "string" then
        ngx.status = 500
        ngx.log(ngx.ERR, "No SA access token in response")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return res.access_token
end

local function keycloak_resource_has_scope(resource_id, scope)
    assert(type(resource_id) == "string")
    assert(type(scope)       == "string")

    local resource = keycloak_get_resource(resource_id)
    if resource == nil then
        ngx.log(ngx.ERR, "Resource id \"" .. resource_id .. "\" not found!")
        return false
    end

    local resource_scopes = keycloak_resource_scope_hash_to_lookup_table(resource.resource_scopes)
    if resource_scopes[scope] == true then
        return true
    else
        return false
    end
end

-----------
-- Public Functions

--[[
    returns the SA access token as a string
--]]
function keycloak.service_account_token()
    -- TODO: cache

    local access_token = keycloak_get_service_account_token()
    assert(type(access_token) == "string")

    return access_token
end

--[[
    Gets the authorization decision for a given access token to access a resource ID

    access_token (string): end-user access token from openidc session
    resource_id  (string): resource ID to evaluate permissions

    returns a table with keycloak's response if the user is authorized:
    {
        'result': true
    }

    returns false if user is denied access
--]]
function keycloak.decision(access_token, resource_id)
    assert(type(access_token) == "string")
    assert(type(resource_id)  == "string")

    -- TODO: cache
    local decision,err = keycloak_get_decision(access_token, resource_id)

    -- TODO: handle err... not sure when KC is allowed to return 403

    return decision,err
end

function keycloak.authenticate(openidc_opts)
    local openidc_opts = openidc_opts or {}

    local opts                          = keycloak_openidc_opts(openidc_opts)
    local res, err, target_url, session = openidc.authenticate(opts)

    -- close the session to clear locks
    session:close()

    if err ~= nil then
        ngx.status = 500
        ngx.log(ngx.ERR, "openidc.authenticate() returned error: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return ngx.HTTP_OK
end

-- invalidate all server-wide caches
function keycloak.invalidate_caches()
    for _,cache in ipairs(keycloak_caches) do
        keycloak_cache_invalidate(cache)
    end
end

-- checks authorization for the resource
-- returns ngx.HTTP_OK (200) for authorized users
-- returns ngx.HTTP_FORBIDDEN (403) for unauthorized users
-- stops execution on errors
function keycloak.authorize()
    -- TODO: authorization may not be enabled for the resource

    local session = r_session.open()

    if session.present == nil then
        session:close()
        ngx.log(ngx.DEBUG, "No session present: access forbidden.")
        return ngx.HTTP_FORBIDDEN
    end

    local session_token = session.data.access_token
    session:close()

    -- catch empty access token
    if session_token == nil then
        ngx.log(ngx.ERR, "Session token is nil: access forbidden.")
        return ngx.HTTP_FORBIDDEN
    end

    -- session_token is not null: check type
    assert(type(session_token) == "string")

    ngx.log(ngx.DEBUG, "Matching URI with Keycloak resources")
    local resource_id = keycloak_resourceid_for_request()

    -- this defines the default policy for logged-in users.
    -- We are denying access to anything that doesn't match a resource in KeyCloak.
    -- TODO: this should be based on the "enforcing" mode in KeyCloak
    -- forbidden if no matching resources found
    if resource_id == nil then
        ngx.log(ngx.ERR, "No matching resources: access forbidden.")
        return ngx.HTTP_FORBIDDEN
    end

    -- we have a resource match
    ngx.log(ngx.DEBUG, "Matched resource ID: " .. resource_id)

    -- TODO: cache session_token,resource_id,decision
    local decision,decision_err = keycloak.decision(session_token,resource_id)
    -- TODO: decision request will return 403 error if no permissions mapped to resource!

    -- catch decision unexpected return type
    if type(decision) ~= "table" then
        ngx.status = 500
        ngx.log(ngx.ERR, "Unexpected Keycloak decision return data type: " .. type(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    -- catch authorization error (eg. not authorized)
    if decision.error ~= nil then
        ngx.log(ngx.ERR, "Keycloak returned authorization error: " .. cjson_s.encode(decision))
        return ngx.HTTP_FORBIDDEN
    end
    -- catch unknown Keycloak response
    if decision.result ~= true then
        ngx.status = 500
        ngx.log(ngx.ERR, "Unexpected Keycloak decision content: " .. cjson_s.encode(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.log(ngx.DEBUG, "Keycloak authorization successful.")
    -- authz successful
    return ngx.HTTP_OK
end

-- returns true if the resource ID has the configured "anonymous scope" attached
function keycloak.authorize_anonymous(anonymous_scope)
    local config = keycloak_config()
    local anonymous_scope = anonymous_scope or config["anonymous_scope"]

    -- decline to make a decision if anonymous enforcing disabled
    if config["anonymous_policy_mode"] == "disabled" then
        return ngx.DECLINED
    end

    local resource_id = keycloak_resourceid_for_request()

    -- no resource found with matching URI, so defer to anonymous policy mode
    if resource_id == nil then
        if config["anonymous_policy_mode"] == "permissive" then
            return ngx.HTTP_OK
        elseif config["anonymous_policy_mode"] == "enforcing" then
            return ngx.HTTP_UNAUTHORIZED
        else -- invalid anonymous_policy_mode
            ngx.log(ngx.ERR, "Unexpected anonymous_policy_mode: " .. tostring(config["anonymous_policy_mode"] == "enforcing"))
            return ngx.DECLINED
        end
    end

    if keycloak_resource_has_scope(resource_id,anonymous_scope) == true then
        return ngx.HTTP_OK
    else
        return ngx.HTTP_UNAUTHORIZED
    end
end

-----------
-- Bless keycloak table as object
keycloak.__index = keycloak
return keycloak
