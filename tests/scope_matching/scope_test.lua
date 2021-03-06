local cjson     = require("cjson")
local cjson_s   = require("cjson.safe")
local inspect   = require("inspect")

local string    = string
local ipairs    = ipairs
local pairs     = pairs
local type      = type

-- BEGIN Nginx test harness
local ngx = {}

function ngx.log(level, message)
    print(level .. ": " .. message)
end

ngx.DEBUG = "DEBUG"
ngx.ERR = "ERROR"
ngx.HTTP_FORBIDDEN = "403"
ngx.HTTP_INTERNAL_SERVER_ERROR = "500"
ngx.HTTP_OK = "200"
function ngx.exit() os.exit() end
ngx.status = ''

-- END Nginx test harness

-- initialize the resty-keycloak instance
-- TODO: resolve all of the different ways the config file (keycloak.json) path could be provided to the extension. The config data needs to be loaded early.
local keycloak = {
    _VERSION = "0.0.1"
}

-- default configuration
local keycloak_default_config = {
    public_access_scope = "read-public",
}

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

-----------
-- Utility Functions

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

-- converts HTTP method into Keycloak scope or "extended" if unknown
-- eg. GET => read
local function keycloak_request_method_to_scope(method)
    assert(type(method) == "string")

    local scope = "extended" -- this scope is returned for unknown HTTP methods (eg. WebDAV)

    -- if we have mapped the HTTP request method to a Keycloak scope, use that
    if keycloak_scope_for_method[method] ~= nil then
        scope = keycloak_scope_for_method[method]
    end

    return scope
end

local function keycloak_resource_set()
    return {
        "e06a803c-0da4-414d-a29d-269b1fbf8501",
        "ffb605ca-5d5d-4f57-b24e-e5536d370e7b",
        "87ea36a2-27a7-4b7b-b939-62a11bb5c5ad"
    }
end

local function keycloak_resource(resource_id)
    assert(type(resource_id) == "string")

    local resources = {}

    resources['e06a803c-0da4-414d-a29d-269b1fbf8501'] = {
        name = "/",
        owner = {
          id = "31c4c56d-3fdf-43a1-ba84-ac5c1bd7d4f1"
        },
        ownerManagedAccess = false,
        displayName = "Site root",
        attributes = { },
        _id = "e06a803c-0da4-414d-a29d-269b1fbf8501",
        uris = { "/*", "/" },
        resource_scopes = {
            { name = "read-public" },
            { name = "view" }
        },
        scopes = {
            { name = "read-public" },
            { name = "view" }
        }
      }

      resources["ffb605ca-5d5d-4f57-b24e-e5536d370e7b"] = {
        name = "/groupone/secrets/",
        owner = {
          id = "31c4c56d-3fdf-43a1-ba84-ac5c1bd7d4f1"
        },
        ownerManagedAccess = true,
        displayName = "Group One Secrets",
        attributes = { },
        _id = "ffb605ca-5d5d-4f57-b24e-e5536d370e7b",
        uris = { "/groupone/secrets/*", "/groupone/secrets/" },
        resource_scopes = { }
      }

      resources["87ea36a2-27a7-4b7b-b939-62a11bb5c5ad"] = {
        name = "Group Secrets",
        owner = {
          id = "31c4c56d-3fdf-43a1-ba84-ac5c1bd7d4f1"
        },
        ownerManagedAccess = true,
        attributes = { },
        _id = "87ea36a2-27a7-4b7b-b939-62a11bb5c5ad",
        uris = { "/*/secrets/*", "/*/secrets/" },
        resource_scopes = { }
      }

    return resources[resource_id]
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

-----------
-- Public Functions

--[[
    Converts a table (possibly nested) into a string for display or debug logging

    table (table)   : from keycloak_realm_discovery_endpoints
    depth (interger): indent level (default = 0)

    returns a human-readble string representation of the table input
--]]
function keycloak.dumpTable(table, depth)
    local depth = depth or 0
    local debug_out = ""

    for k,v in pairs(table) do
        if (type(v) == "table") then
            debug_out = debug_out .. string.rep("  ", depth) .. k .. ":" .. "\n"
            keycloak.dumpTable(v, depth+1)
        else
            debug_out = debug_out .. string.rep("  ", depth) .. ": " .. tostring(v) .. "\n"
        end
    end

    return debug_out
end

-----------
-- Bless keycloak table as object
keycloak.__index = keycloak

print(keycloak_resourceid_for_request("/groupone/secrets/", "POST"))
