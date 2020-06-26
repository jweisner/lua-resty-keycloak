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

-- keycloak_openidc_defaults -- populated at the bottom of this script

local keycloak = {
    _VERSION = "0.0.1"
}

-- merge tables. Table "one" has priority
-- eg. keycloak_merge(config, defaults)
local function keycloak_merge(one, two)
    local one = one or {}
    local two = two or {}
    -- merge opts
    for k, v in pairs(one) do two[k] = v end

    return two
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

function keycloak.openidc_opts(opts)
    local opts = opts or {}
    local config = keycloak.config()
    local defaults = {
        redirect_uri = "/callback",
        discovery = keycloak_openid_discovery_url(),
        client_id = config.resource,
        client_secret = config.credentials.secret
    }


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
-- invalidate all server-wide caches
function keycloak.invalidate_caches()
    for i,cache in ipairs(keycloak_caches) do
        keycloak_cache_invalidate(cache)
    end
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

function keycloak.get_discovery_doc()
    local openidc_opts = { }
    openidc_opts["discovery"] = keycloak_discovery_url()
    local discovery, err = openidc.get_discovery_doc(openidc_opts)
    return discovery, err
end

function keycloak.discovery()
    -- TODO: use openidc discovery cache
    local discovery, err = keycloak.get_discovery_doc()

    if err then
        ngx.status = 500
        log(ERROR, "Error getting keycloak discovery: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    else
        return discovery, nil
    end
end

-- function keycloak.enforce(uri, scope)
--     scope = scope or "view"
--     local body = {}
--     local headers = {}
--     body.__index = body-- this needs to come from somewhere
-- end

-- this function is adapted from openidc.call_token_endpoint()
local function keycloak_call_endpoint(endpoint_name, headers, body, method)
    local endpoint_name = endpoint_name or "token_endpoint"
    local headers = headers or {}
    local body = body or {}
    local method = method or "POST"

    local discovery = keycloak.discovery()
    local config = keycloak.config()

    -- TODO: check that we have an endpoint for this
    local endpoint_url = discovery[endpoint_name]

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

    local httpc = http.new()
    -- TODO: timeouts
    -- TODO: proxy

    local httpc_params = {
        method = method,
        body = ngx.encode_args(body),
        headers = headers,
        ssl_verify = true,
        keepalive = false
    }

    local res, err = httpc:request_uri(endpoint_url, httpc_params)

    if err then
        ngx.status = 500
        log(ERROR, "Error calling endpoint "..endpoint_name..": " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- TODO: check for json decode errors
    return cjson_s.decode(res.body), err
end

function keycloak.service_account_token()
    local endpoint_name = "token_endpoint"
    local config = keycloak.config()

    local body = {
        grant_type = "client_credentials"
    }

    local res, err = keycloak_call_endpoint(endpoint_name, {}, body)

    return res.access_token
end

function keycloak.get_enforcement(access_token)
    local endpoint_name = "token_endpoint"
    local config = keycloak.config()
    -- TODO: error if access_token nil
    local headers = {
        ["Authorization"] = "Bearer " .. access_token
    }

    local body = {
        grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket",
        audience = config.resource,
        response_mode = "decision"
    }

    local res, err = keycloak_call_endpoint(endpoint_name, headers, body)
    return res, err
end

keycloak.__index = keycloak

local keycloak_openidc_defaults = {
    redirect_uri  = "/callback",
    discovery     = keycloak_discovery_url("openid"),
    client_id     = keycloak_config()["resource"],
    client_secret = keycloak_config()["credentials"]["secret"]
}

function keycloak.authenticate(opts)
    local opts = opts or {}
    opts = keycloak_merge(opts, keycloak_openidc_defaults)
    local res, err, target_url, session = openidc.authenticate(opts)

    return res, err, target_url, session
end

return keycloak
