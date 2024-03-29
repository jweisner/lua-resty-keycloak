local require      = require
local cjson        = require("cjson")
local cjson_s      = require("cjson.safe")
local messagepack  = require("MessagePack")
local r_env        = require("resty.env")
local http         = require("resty.http")
local r_session    = require("resty.session")
local openidc      = require("resty.openidc")
local redis        = {} -- TODO dynamically load the redis code if needed
local string       = string
local ipairs       = ipairs
local pairs        = pairs
local type         = type
-- TODO use the dynamic loader here to avoid "undefined global ngx"
local ngx_harness  = {}
ngx_harness["log"] = function (log, message) end
local ngx          = ngx or ngx_harness -- TODO dynamically load Nginx test harness
-- TODO investigate https://github.com/openresty/test-nginx

-- TODO split this code into libraries and dynamically load the larger parts
-- TODO implement "busted" unit testing
-- TOTO I miss the rains down in Africa
-- TODO migrate to OOP?
-- TODO clean up unnecessary DEBUG statements

-- initialize the resty-keycloak instance
local keycloak = {
    _VERSION = "0.0.1"
}

-- default configuration
local keycloak_default_config = {
    anonymous_policy_mode = "permissive", -- enforcing, permissive, disabled : enforcing requires anonymous_scope to be in the resource scopes
    anonymous_scope       = "read-public", -- keycloak scope to allow anonymous
    auth_server_url       = "http://localhost:8080/auth",
    callback_uri          = "/callback",
    client_id             = "nginx",
    client_secret         = "00000000-0000-0000-0000-000000000000",
    realm                 = "master",
}

-- token values to export to Nginx variable space
-- these will have to be added to the token in the IDP configuration
-- All of the oid_* values must be created in Nginx first
-- TODO make token attributes configurable in Nginx
keycloak_default_config["export_token_attributes"] = {
    active     = "oid_active",
    email      = "oid_email",
    username   = "oid_username",
    given_name = "oid_given_name",
    first_name = "oid_first_name",
    name       = "oid_name"
}

-- list of all caches used in this code
-- this is used by keycloak.invalidate_caches()
--
-- IMPORTANT: each one of these needs a "lua_shared_dict" in Nginx config 00-openresty.conf
local keycloak_caches = {
    "keycloak_anonymous",
    "keycloak_config",
    "keycloak_discovery",
    "keycloak_request_resourceid",
    "keycloak_resource_set",
    "keycloak_resource",
    "keycloak_service_account",
    -- add any other caches we use here
}

-- keycloak cache expiries
local keycloak_cache_expiry = { }
keycloak_cache_expiry["keycloak_anonymous"]          =           10
keycloak_cache_expiry["keycloak_config"]             = 24 * 60 * 60
keycloak_cache_expiry["keycloak_discovery"]          = 24 * 60 * 60
keycloak_cache_expiry["keycloak_request_resourceid"] =      10 * 60
keycloak_cache_expiry["keycloak_resource_set"]       =      30 * 60
keycloak_cache_expiry["keycloak_resource"]           =      10 * 60

-- minimum seconds remaining in token lifetime to attempt early renewal
local keycloak_token_renewal_threshold =       2 * 60

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
-- TODO move timeouts to config
local keycloak_http_timeouts = {
    connect_timeout = 10000,
    send_timeout    = 5000,
    read_timeout    = 5000,
}

-- attributes of a token resource returned from the token endpoint that we will cache
local keycloak_token_res_attributes = {
    "access_token",
    "expires_in",
    "refresh_expires_in",
    "refresh_token",
    "token_type",
    "not-before-policy",
    "scope",
    "expires_at",
    "refresh_expires_at",
    "issued_at",
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

-- serializes data for shared cache or kv store
local function keycloak_serialize(data)
    if data == nil then return data end -- only pack if there is data to pack
    return messagepack.pack(data)
end

-- serializes data for shared cache or kv store
local function keycloak_unserialize(packed)
    if packed == nil then return packed end -- only unpack if there is data to unpack

    return messagepack.unpack(packed)
end

-- This function is copied from resty.openidc
-- invalidate values of server-wide cache
local function keycloak_cache_invalidate(dictname)
    -- TODO redis integration
    local dict = ngx.shared[dictname]

    if not dict then
        ngx.log(ngx.WARN, "WARNING: Missing Nginx lua_shared_dict " .. dictname)
    end

    if dict then
        ngx.log(ngx.DEBUG, "DEBUG: flushing cache for " .. dictname)
        dict.flush_all(dict)
        local nbr = dict.flush_expired(dict)
    end
end

-- This function is copied from resty.openidc
-- set value in server-wide cache if available
local function keycloak_cache_set(dictname, key, value, exp)
    assert(type(dictname) == "string")
    assert(type(key)      == "string")
    assert(type(exp)      == "number" and not ( tostring(exp):find('%.')) ) -- forces integer

    -- TODO redis integration
    local nginxdict = ngx.shared[dictname]

    -- invalid or unset Nginx dict
    if not nginxdict then
        ngx.log(ngx.WARN, "WARNING: Missing Nginx lua_shared_dict " .. dictname)
        return false
    end

    -- invalidate the cache on zero expiry
    if exp == 0 then
        ngx.log(ngx.DEBUG, "Received zero expiry, invalidating dict: " .. dictname)
        keycloak_cache_invalidate(dictname)
        return true
    end

    local success, err, forcible = nginxdict:set(key, keycloak_serialize(value), exp)
    if err then
        ngx.log(ngx.ERR, "Nginx dict rejected incompatible data: " .. tostring(value))
        ngx.log(ngx.DEBUG, "Nginx rejected data. Flushing dict: " .. dictname)
        keycloak_cache_invalidate(dictname)
    else
        ngx.log(ngx.DEBUG, "DEBUG: cache set: success=", success, " err=", err, " forcible=", forcible)
    end
end

-- This function is copied from resty.openidc
-- retrieve value from server-wide cache if available
local function keycloak_cache_get(dictname, key)
    -- TODO redis integration
    local dict = ngx.shared[dictname]
    local value

    if not dict then
        ngx.log(ngx.WARN, "WARNING: Missing Nginx lua_shared_dict " .. dictname)
    end

    if dict then
        value = keycloak_unserialize(dict:get(key))
        if value then ngx.log(ngx.DEBUG, "DEBUG: cache hit: dictname=", dictname, " key=", key) end
    end
    return value
end

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
    local config = keycloak_cache_get("keycloak_config", "config")

    if config then
        ngx.log(ngx.DEBUG, "DEBUG: keycloak config cache HIT")
    end

    if not config then
        ngx.log(ngx.DEBUG, "DEBUG: keycloak config cache MISS")
        config = keycloak_get_config()
        keycloak_cache_set("keycloak_config", "config", config, keycloak_cache_expiry["keycloak_config"])
    end

    return config
end

--[[
    Clear all Nginx exported variables
    This will be called by the cache flush callback, not implemented yet
]]
local function keycloak_clear_export_attributes()
    local config = keycloak_config()

    for key, value in pairs(config["export_token_attributes"]) do
        ngx.var[value] = "-"
    end

    ngx.var.oid_realm_roles    = ""
    ngx.var.oid_resource_roles = ""
end

--[[
    exports token attributes to Nginx variables

    returns nothing
]]
local function keycloak_export_attributes(token_attributes)
    assert(type(token_attributes) == "table", "keycloak_export_attributes(): token_attributes: expected table, got " .. type(token_attributes))

    local config = keycloak_config()

    for key, value in pairs(config["export_token_attributes"]) do
        ngx.var[value] = token_attributes[key] or "-"
    end

    -- "realm_roles" = join(',', realm_access['roles'])
    --     "realm_access": {
    --         "roles": [
    --             "offline_access",
    --             "uma_authorization",
    --             "Current Employee"
    --         ]
    --     },
    if type(token_attributes.realm_access) == "table" and type(token_attributes.realm_access.roles) == "table" then
        ngx.var.oid_realm_roles = table.concat(token_attributes.realm_access.roles, ",")
    else
        ngx.var.oid_realm_roles = ""
    end

    -- "resource_roles" = join(',', resource_access['account']['roles'])
    --     "resource_access": {
    --         "account": {
    --             "roles": [
    --                 "manage-account",
    --                 "manage-account-links",
    --                 "view-profile"
    --             ]
    --         }
    --     },
    if type(token_attributes.resource_access) == "table" and type(token_attributes.resource_access.account.roles) == "table" then
        ngx.var.oid_resource_roles = table.concat(token_attributes.resource_access.account.roles, ",")
    else
        ngx.var.oid_resource_roles = ""
    end
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

    -- check the error return from http client
    if err then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error fetching " .. endpoint_type .. " discovery at " .. discovery_url .. " : " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- check the HTTP response code from the discovery request
    if res.status ~= 200 then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error fetching " .. endpoint_type .. " discovery at " .. discovery_url .. " : " .. "code:" .. res.status .. " reason: " .. res.reason)
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

    local discovery = keycloak_cache_get("keycloak_discovery", endpoint_type)

    if not discovery then
        discovery = keycloak_get_discovery(endpoint_type)
        keycloak_cache_set("keycloak_discovery", endpoint_type, discovery, keycloak_cache_expiry["keycloak_discovery"])
    end

    return discovery
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
            body.client_id = config.client_id
        end

        -- make sure client secret is included (resource server authentication)
        if body.client_secret == nil then
            body.client_secret = config.client_secret
        end
    end

    -- configure httpc timeouts (connect_timeout, send_timeout, read_timeout)
    httpc:set_timeouts(
        keycloak_http_timeouts["connect_timeout"],
        keycloak_http_timeouts["send_timeout"],
        keycloak_http_timeouts["read_timeout"]
    )

    -- TODO do we need to do anything with httpc proxy here for proxied servers?

    local httpc_params = {
        method     = method,
        body       = ngx.encode_args(body),
        headers    = headers,
        ssl_verify = true,
        keepalive  = false
    }

    local res, err = httpc:request_uri(endpoint_url, httpc_params)
    -- TODO check response HTTP error code
    -- check for HTTP client errors
    if err then
        ngx.log(ngx.ERR, "WARNING: Error calling endpoint " .. endpoint_name .. ": " .. err) -- non-fatal error
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
    assert(type(access_token) == "string") -- access_token from session.data
    assert(type(resource_id)  == "string")

    local endpoint_name = "token_endpoint"
    local endpoint_type = "uma2"

    local config        = keycloak_config()

    local headers = {
        ["Authorization"] = "Bearer " .. access_token -- session token
    }

    local body = {
        grant_type    = "urn:ietf:params:oauth:grant-type:uma-ticket",
        audience      = config.client_id,
        permission    = resource_id,
        response_mode = "decision"
    }

    -- TODO validate what happens here with permission denied. KC will return 403?
    local res,err = keycloak_call_endpoint(endpoint_type, endpoint_name, headers, body)

    -- TODO handle err here or in wrapper?

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

    -- handle err
    if err ~= nil then
        keycloak_cache_invalidate("keycloak_resource_set")
        ngx.status = 500
        ngx.log(ngx.ERR, "Error getting resource_set: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- if the service account token is not valid, the endpoint returns an error as a JSON response, but err is nil
    if resource_set["error"] ~= nil then
        keycloak_cache_invalidate("keycloak_resource_set")
        keycloak_cache_invalidate("keycloak_service_account")
    end

    return resource_set
end

local function keycloak_resource_set()
    local resource_set = keycloak_cache_get("keycloak_resource_set", "resource_set")

    if not resource_set then
        resource_set = keycloak_get_resource_set()
        ngx.log(ngx.DEBUG, "DEBUG: Returning fetched resource set from endpoint: " .. cjson_s.encode(resource_set))
        keycloak_cache_set("keycloak_resource_set", "resource_set", resource_set, keycloak_cache_expiry["keycloak_resource_set"])
    else
        ngx.log(ngx.DEBUG, "Returning resource set from cache: " .. cjson_s.encode(resource_set))
    end

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

    -- Handle error from call_endpoint
    -- NOTE: this is not a fatal error, but needs to be properly handled by the callee
    if err ~= nil then
        ngx.log(ngx.ERR, "Error fetching resource " .. resource_id .. " from Keycloak: " .. err)
        resource = nil
    end

    return resource
end

local function keycloak_resource(resource_id)
    assert(type(resource_id) == "string")

    -- attempt to retrieve resource from Nginx cache
    local resource = keycloak_cache_get("keycloak_resource", resource_id)

    -- retrieve resource from KeyCloak
    if not resource then
        ngx.log(ngx.DEBUG, "DEBUG: cache miss fetching resource " .. resource_id)
        resource = keycloak_get_resource(resource_id)
    end

    -- sanity check on resource before caching
    if resource and (type(resource) == "table") then
        keycloak_cache_set("keycloak_resource", resource_id, resource, keycloak_cache_expiry["keycloak_resource"])
    else
        ngx.log(ngx.ERR, "Unable to fetch " .. resource_id)
        resource = nil
    end

    return resource
end

local function keycloak_get_resources(fail_on_error)
    local fail_on_error = fail_on_error or false
    assert(type(fail_on_error) == "boolean")
    local resource_set  = keycloak_resource_set()
    local resources     = {}
    local count         = 0
    local try_again     = false

    for k,resource_id in ipairs(resource_set) do
        local resource = keycloak_resource(resource_id)
        if resource ~= nil then
            resources[resource_id] = keycloak_resource(resource_id)
            count = count +1
        else
            -- if the resource fails to fetch, try again
            -- this is logged in keycloak_resource()
            try_again = true
            break
        end
    end

    -- if we got an error fetching a resource, flush the caches and try again
    if try_again and fail_on_error then
        ngx.status = 500
        ngx.log(ngx.ERR, "Failed to fetch resources")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- try again with a recursive call one last time
    -- flush resource list and resource caches
    if try_again and not fail_on_error then
        keycloak_cache_invalidate("keycloak_resource_set")
        keycloak_cache_invalidate("keycloak_resource")
        resources,count = keycloak_get_resources(true) -- fail_on_error = true
    end

    return resources,count
end

local function keycloak_resources()
    -- this is not cached because it is only pulling the details from cache or UMA2 endpoint
    -- this is just a wrapper for keycloak_get_resources()
    return keycloak_get_resources()
end

-- this global has to be declared here; after all of the required functions are defined, and before keycloak_openidc_opts()
local keycloak_openidc_defaults = {
    -- TODO callback URI needs to be configurable
    client_id     = keycloak_config()["client_id"],
    client_secret = keycloak_config()["client_secret"],
    discovery     = keycloak_discovery_url("openid"),
    redirect_uri  = keycloak_config()["callback_uri"],
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
    local request_uri    = request_uri or ngx.var.request_uri
    local request_method = request_method or ngx.req.get_method()
    -- cache key is the request method plus the request uri
    --   eg. GET/foo/bar.html
    local cache_key      = ngx.md5(request_method .. request_uri) -- shared cache key

    local cached_resourceid = keycloak_cache_get("keycloak_request_resourceid", cache_key)
    if cached_resourceid then
        return cached_resourceid
    end

    local request_method_scope      = keycloak_request_method_to_scope(request_method)
    local resources,resources_count = keycloak_resources()

    assert(type(resources) == "table")

    ngx.log(ngx.DEBUG, "DEBUG: request_uri:" .. request_uri .. " request_method:" .. request_method .. " method_scope:" .. request_method_scope .. " resource count:" .. resources_count)
    ngx.log(ngx.DEBUG, "DEBUG: fetched resources: " .. cjson_s.encode(resources))

    -- initialize "best match"
    local found_depth = 0
    local found       = nil -- this will be replaced by the ID of the closest uri match. nil if none

    for resource_id,resource in pairs(resources) do
        local resource_name = tostring(resource.name)
        ngx.log(ngx.DEBUG, "DEBUG: Trying resource: \"" .. resource_name .. "\"")

        local resource_scopes = keycloak_resource_scope_hash_to_lookup_table(resource.resource_scopes)
        -- search for any method scopes (scopes mapped to HTTP methods)
        -- if there are any associated method scopes, the request method must match
        local resource_has_method_scopes = keycloak_resource_scopes_include_request_methods(resource_scopes)

        local resource_scopes_include_request_method = false
        if resource_has_method_scopes then
            ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\" has method scopes.")
            -- check if the request scope is in the associated resource scopes
            if resource_scopes[request_method_scope] ~= nil then
                resource_scopes_include_request_method = true
                ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": found matching scope: " .. request_method_scope)
            else
                ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": no matching scopes.")
            end
        else
            ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\" no method scopes.")
        end

        -- only test the resource URIs if the request method matches the resource scope
        -- or the resource doesn't list any associated scopes
        if resource_scopes_include_request_method or (resource_has_method_scopes == false) then
            ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": passed scope check, testing " .. #resource.uris .. " resource URI patterns: " .. table.concat(resource.uris, ","))
            for _,uri in ipairs(resource.uris) do
                ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": testing pattern:" .. uri .. " against request:" .. request_uri)
                local match_depth = keycloak_uri_path_match(request_uri,uri) or 0
                if match_depth > 0 then
                    ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": URI pattern \"" .. uri .. "\" matches at depth " .. match_depth)
                    if match_depth > found_depth then
                        ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": URI pattern \"" .. uri .. "\" is deeper (" .. match_depth .. ") than previous match (" .. found_depth .. ")")
                        found_depth = match_depth
                        found       = resource_id
                    else
                        ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": URI pattern \"" .. uri .. "\" is shallower (" .. match_depth .. ") than previous match (" .. found_depth .. ")")
                    end
                else
                    ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": URI pattern \"" .. uri .. "\" does not match")
                end
            end
        else
            ngx.log(ngx.DEBUG, "DEBUG: Resource: \"" .. resource_name .. "\": skipping URI check: disqualified by method scope.")
        end
    end

    -- found is the id of the clostest resource match
    -- stop here if no matches were found
    if found == nil then
        ngx.log(ngx.DEBUG, "DEBUG: no resource matches for URI and method")
        return nil
    end

    assert(type("found") == "string")
    keycloak_cache_set("keycloak_request_resourceid", cache_key, found, keycloak_cache_expiry["keycloak_request_resourceid"])
    return found
end

--[[
    Check if data returned from a call to the token endpoint appears to be
    valid token data

    token_res (any): data to evaluate

    returns:
        token_res: the data that was evaluated
        err: an error message if the data appears invalid
]]
local function keycloak_validate_token_resource(token_res)
    if type(token_res) ~= "table" then
        return token_res, "Token resource is not a table"
    end

    if type(token_res["access_token"]) ~= "string" then
        return token_res, "access_token missing"
    end

    if type(token_res["expires_in"]) ~= "number" then
        return token_res, "expires_in missing"
    end

    if type(token_res["refresh_token"]) ~= "string" then
        return token_res, "refresh_token missing"
    end

    if type(token_res["refresh_expires_in"]) ~= "number" then
        return token_res, "refresh_expires_in missing"
    end

    if type(token_res["token_type"]) ~= "string" then
        return token_res, "token_type missing"
    end

    if type(token_res["not-before-policy"]) ~= "number" then
        return token_res, "not-before-policy missing or invalid"
    end

    return token_res,nil
end

--[[
    Take the response data from a token endpoint request and copy the
    data to a new table adding "expires_at" and "issued_at" epoch times

    token_data (table): a response table from the OpenID token_endpoint

    returns new table with "expires_at" values for token
    and refresh token

    example input data:
    {
        access_token       = "access token as string",
        expires_in         = 300,
        refresh_token      = "refresh token as string",
        refresh_expires_in = 1800,
        ...
    }

    example return data:
    {
        access_token       = "access token as string",
        expires_in         = 300,
        expires_at         = 1618419999,
        issued_at          = 1618419699,
        refresh_token      = "refresh token as string",
        refresh_expires_in = 1800
        refresh_expires_at = 1618421499,
        ...
    }
]]
local function keycloak_set_token_expiry(token_data, issued_at)
    assert(type(token_data) == "table")
    local issued_at = issued_at or ngx.time()

    -- sanity check on token data
    assert(type(token_data["access_token"])       == "string" )
    assert(type(token_data["expires_in"])         == "number" )
    assert(type(token_data["refresh_token"])      == "string" )
    assert(type(token_data["refresh_expires_in"]) == "number" )

    local current_time = ngx.time()

    token_data["issued_at"]          = current_time
    token_data["expires_at"]         = current_time + token_data["expires_in"]
    token_data["refresh_expires_at"] = current_time + token_data["refresh_expires_in"]

    return token_data
end

--[[
    fetch the service account token from Keycloak for the resource server

    returns the service account data from the token endpoint
--]]
local function keycloak_get_service_account_token()
    local endpoint_name = "token_endpoint"
    local endpoint_type = "openid"
    local config        = keycloak_config()

    local body = {
        client_id     = config["client_id"],
        client_secret = config["client_secret"],
        grant_type    = "client_credentials",
    }

    local res, err = keycloak_call_endpoint(endpoint_type, endpoint_name, {}, body)
    local current_time = ngx.time()

    -- check for SA token error
    if err then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error calling endpoint " .. endpoint_name .. ": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- check for error message response
    if res.error ~= nil then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error fetching service account token: " .. res.error .. " message: " .. tostring(res.error_message))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- sanity check on returned data
    res, err = keycloak_validate_token_resource(res)

    if err then
        ngx.status = 500
        ngx.log(ngx.ERR, "Error validating service account token data: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if res.token_type ~= "bearer" then
        ngx.status = 500
        ngx.log(ngx.ERR, "Token endpoint returned unexpected token type: " .. tostring(res.token_type) .. "expecting \"bearer\" token.")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- add derived atttributes
    res = keycloak_set_token_expiry(res, current_time)

    return res
end

local function keycloak_resource_has_scope(resource_id, scope)
    assert(type(resource_id) == "string")
    assert(type(scope)       == "string")

    local resource = keycloak_resource(resource_id)

    -- if there is an error fetching a known resource ID, the UMA2 endpoint
    -- may be down, or the resource may have been recently removed. The safest thing to
    -- do here is flush the caches so other processes don't try to use it again if it
    -- has been removed, and error out with an ISE. This way only one client
    -- gets an error, and it should fix itself on a page refresh
    if resource == nil then
        keycloak_cache_invalidate("keycloak_resource_set")
        keycloak_cache_invalidate("keycloak_resource")
        ngx.status = 500
        ngx.log(ngx.ERR, "Resource id \"" .. resource_id .. "\" not found! Resource caches flushed.")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    assert(type(resource) == "table")

    local resource_scopes = keycloak_resource_scope_hash_to_lookup_table(resource.resource_scopes)
    if resource_scopes[scope] == true then
        return true
    else
        return false
    end
end

--[[
    Introspect the access token to get the attributes

    returns the token attributes as a table
]]
local function keycloak_token_introspect(access_token)
    assert(type(access_token) == "string")

    local config          = keycloak_config()
    local request_headers = {}
    local request_body    = {
        token         = access_token,
        client_id     = config['client_id'],
        client_secret = config['client_secret']
    }

    local token_attributes,err = keycloak_call_endpoint("openid", "introspection_endpoint", request_headers, request_body, {}, "POST")

    -- handle introspection endpoint errors
    if err ~= nil then
        ngx.log(ngx.ERR, "Error introspecting access token: " .. err)
        ngx.status = 500
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- handle introspection content errors
    if token_attributes.error ~= nil then
        ngx.log(ngx.ERR, "Error introspecting access token: " .. token_attributes.error)
        ngx.status = 500
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.log(ngx.DEBUG, "DEBUG: token_attributes: " .. cjson_s.encode(token_attributes))
    assert(type(token_attributes) == "table")
    return token_attributes
end

--[[
    Fetch the token attributes from the session cache or inprospection

    returns the token attributes as a table
]]
local function keycloak_token_attributes(access_token)
    assert(type(access_token) == "string")

    local session = r_session.open()
    local access_token_attributes = session.data.token_attributes

    if type(access_token_attributes) == "table" then
        ngx.log(ngx.DEBUG, "DEBUG: token_attributes cache HIT")
        return access_token_attributes
    end

    return keycloak_token_introspect(access_token)
end

--[[
    Evaluate the time remaining on a token using the renewal threshold

    token (string): an access token
    expiry (number): epoch time of token expiry
    threshold (number): optional seconds remaining threshold for freshness test
]]
local function keycloak_token_is_fresh(expiry, threshold)
    assert(type(expiry) == "number")
    local threshold = threshold or keycloak_token_renewal_threshold
    assert(type(threshold) == "number")

    local seconds_remaining = expiry - threshold - ngx.time()

    if seconds_remaining > 0 then
        -- token time is still valid
        return true
    end

    -- token is expired
    return false
end

-----------
-- Public Functions

--[[
    returns the SA access token as a string

    - if the token needs to be refreshed, refresh the token
    - if the token can't be refreshed, get a new one from SA credentials
--]]
function keycloak.service_account_token()
    local token_res, err     = {}, nil
    local attributes         = keycloak_token_res_attributes
    local renewal_threshold  = keycloak_token_renewal_threshold
    local cache_key          = "keycloak_service_account"
    local token_fresh        = false

    -- attempt to pull all service account token data from cache
    for i,k in ipairs(attributes) do
        token_res[k] = keycloak_cache_get(cache_key, k)
    end

    -- check for valid cache data
    token_res, err = keycloak_validate_token_resource(token_res)

    -- if the cache is missing or the data appears invalid; assume cache miss, destroy resource data
    if err then
        ngx.log(ngx.DEBUG, "DEBUG: Cache miss on " .. cache_key .. ": " .. err)
        token_res = {}
    end

    -- if we have expires_at, check freshness
    if (err == nil) and (type(token_res) == "table") and (type(token_res["expires_at"]) == "number") then
        token_fresh = keycloak_token_is_fresh(token_res["expires_at"])
    end

    -- fetch and store new contents if empty or expired
    if err or (token_fresh ~= true) then
        token_res = keycloak_get_service_account_token()
        -- store cached service account data
        for k,v in pairs(token_res) do
            keycloak_cache_set(cache_key, k, v, (token_res["expires_in"] - renewal_threshold))
        end
    end

    return token_res["access_token"]
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

    return keycloak_get_decision(access_token, resource_id)
end

function keycloak.authenticate(openidc_opts)
    local openidc_opts = openidc_opts or {}

    -- ensure that this resource server has a valid service account access token
    local service_account_token = keycloak.service_account_token()
    assert(type(service_account_token) == "string", "Failed to retrieve service account access_token")

    local opts                          = keycloak_openidc_opts(openidc_opts)
    local res, err, target_url, session = openidc.authenticate(opts)

    if err ~= nil then
        session:close()
        ngx.status = 500
        ngx.log(ngx.ERR, "openidc.authenticate() returned error: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if type(session) ~= "table" then
        ngx.status = 500
        ngx.log(ngx.ERR, "No valid session found. Check for errors in the resty.session driver.")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local session_token = session.data.access_token

    -- TODO dedupe this routine
    -- session_token is not null: check type
    assert(type(session_token) == "string")
    local token_attributes = keycloak_token_attributes(session_token)
    keycloak_export_attributes(token_attributes)

    -- close the session to clear locks
    session:close()

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
    local session = r_session.open()
    local session_token = nil

    -- ensure that this resource server has a valid service account access token
    local service_account_token = keycloak.service_account_token()
    assert(type(service_account_token) == "string", "Failed to retrieve service account access_token")

    if session.present then
        session_token = session.data.access_token
    end

    -- if there is a session and an access token present, try to set OID attributes
    if session.present and (type(session_token) == "string") then
        -- TODO dedupe this routine
        local token_attributes = keycloak_token_attributes(session_token)
        keycloak_export_attributes(token_attributes)
    end

    if session.present == nil then
        session:close()
        ngx.log(ngx.DEBUG, "DEBUG: No session present: access forbidden.")
        return ngx.HTTP_UNAUTHORIZED
    end

    local session_token = session.data.access_token

    -- catch empty access token
    if session_token == nil then
        ngx.log(ngx.WARN, "WARNING: Session token is nil: access forbidden.") -- non-fatal error
        session:close()
        return ngx.HTTP_UNAUTHORIZED
    end

    ngx.log(ngx.DEBUG, "DEBUG: Matching URI with Keycloak resources")
    local resource_id = keycloak_resourceid_for_request()

    -- this defines the default policy for logged-in users.
    -- We are denying access to anything that doesn't match a resource in KeyCloak.
    -- forbidden if no matching resources found
    if resource_id == nil then
        ngx.log(ngx.WARN, "WARNING: No matching resources: access forbidden.") -- non-fatal error
        session:close()
        return ngx.HTTP_FORBIDDEN
    end

    -- we have a resource match
    ngx.log(ngx.DEBUG, "Matched resource ID: " .. resource_id)

    -- set up authorization table in session if not present
    if session.data.authorized == nil then
        ngx.log(ngx.DEBUG, "DEBUG: No authorization table found in session data.")
        session.data.authorized = {}
    end

    assert(type(session.data.authorized) == "table")

    -- return cached authorization result if present
    if session.data.authorized[resource_id] ~= nil then
        ngx.log(ngx.DEBUG, "DEBUG: Found existing decision (" .. session.data.authorized[resource_id] .. ") in session for resource id: " .. resource_id)
        session:close()
        return session.data.authorized[resource_id]
    end

    -- decision request will return 403 error if no permissions mapped to resource
    local decision,decision_err = keycloak.decision(session_token,resource_id)

    -- catch decision unexpected return type
    if type(decision) ~= "table" then
        session:close()
        ngx.status = 500
        ngx.log(ngx.ERR, "Unexpected Keycloak decision return data type: " .. type(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    -- catch authorization error (eg. not authorized)
    if decision.error ~= nil then
        ngx.log(ngx.DEBUG, "DEBUG: Setting HTTP_FORBIDDEN in session for resource_id: " .. resource_id)
        -- cache the result in the session data
        session.data.authorized[resource_id] = ngx.HTTP_FORBIDDEN
        session:save()
        session:close()
        ngx.log(ngx.WARN, "WARNING: Keycloak returned authorization error: " .. cjson_s.encode(decision)) -- non-fatal error
        return ngx.HTTP_FORBIDDEN
    end
    -- catch unknown Keycloak response
    if decision.result ~= true then
        session:close()
        ngx.status = 500
        ngx.log(ngx.ERR, "Unexpected Keycloak decision content: " .. cjson_s.encode(decision))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.log(ngx.DEBUG, "DEBUG: Keycloak authorization successful resource_id: " .. resource_id)
    ngx.log(ngx.DEBUG, "DEBUG: Setting HTTP_OK in session for resource_id: " .. resource_id)
    -- cache the result in the session data
    session.data.authorized[resource_id] = ngx.HTTP_OK
    session:save()
    session:close()
    -- authz successful
    return ngx.HTTP_OK
end

-- returns true if the resource ID has the configured "anonymous scope" attached
function keycloak.authorize_anonymous(anonymous_scope)
    local config = keycloak_config()
    local anonymous_scope = anonymous_scope or config["anonymous_scope"]

    -- ensure that this resource server has a valid service account access token
    local service_account_token = keycloak.service_account_token()
    assert(type(service_account_token) == "string", "Failed to retrieve service account access_token")

    -- decline to make a decision if anonymous enforcing disabled
    if config["anonymous_policy_mode"] == "disabled" then
        ngx.log(ngx.DEBUG, "DEBUG: anonymous mode disabled")
        return ngx.DECLINED
    end

    -- export session attributes if we have an existing session
    local session = r_session.open()
    if session.present and type(session.data.access_token) == "string" then
        -- TODO dedupe this routine
        local token_attributes = keycloak_token_attributes(session.data.access_token)
        keycloak_export_attributes(token_attributes)
    end
    session:close()

    local cache_result = keycloak_cache_get("keycloak_anonymous", ngx.md5(ngx.request_uri))

    if cache_result then
        ngx.log(ngx.DEBUG, "DEBUG: returning cached anonymous result: " .. tostring(cache_result))
        return cache_result
    else
        ngx.log(ngx.DEBUG, "DEBUG: keycloak_anonymous cache miss")
    end

    local resource_id = keycloak_resourceid_for_request()

    -- no resource found with matching URI, so defer to anonymous policy mode
    if resource_id == nil then
        if config["anonymous_policy_mode"] == "permissive" then
            ngx.log(ngx.DEBUG, "DEBUG: no resource found. Permissive policy. returning HTTP_OK")
            return ngx.HTTP_OK
        elseif config["anonymous_policy_mode"] == "enforcing" then
            ngx.log(ngx.DEBUG, "DEBUG: no resource found. Enforcing policy. returning HTTP_UNAUTHORIZED")
            return ngx.HTTP_UNAUTHORIZED
        else -- invalid anonymous_policy_mode
            ngx.log(ngx.ERR, "Unexpected anonymous_policy_mode: " .. tostring(config["anonymous_policy_mode"])) -- fatal
            return ngx.DECLINED
        end
    end

    -- policy server has a resource ID that matches the request
    if keycloak_resource_has_scope(resource_id,anonymous_scope) == true then
        ngx.log(ngx.DEBUG, "DEBUG: found anonymous scope \"" .. tostring(anonymous_scope) .. "\" for resource_id: " .. tostring(resource_id) .. ": anonymous access granted.")
        return ngx.HTTP_OK
    else
        ngx.log(ngx.DEBUG, "DEBUG: anonymous scope not found: anonymous access denied. Returning " .. ngx.HTTP_UNAUTHORIZED)
        return ngx.HTTP_UNAUTHORIZED
    end
end

-- provides insight into the session data
function keycloak.dump_session_data()
    local session = r_session.open()

    ngx.say("*** Session Data ***")
    for k,v in pairs(session.data) do
        ngx.say(k .. ": " .. cjson_s.encode(v))
    end

    session:close()
end
-----------
-- Bless keycloak table as object
keycloak.__index = keycloak
return keycloak
