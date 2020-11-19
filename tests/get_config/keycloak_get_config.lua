local inspect = require("inspect")

-- default configuration
local keycloak_default_config = {
    anonymous_policy_mode = "permissive", -- enforcing, permissive, disabled : enforcing requires anonymous_scope to be in the resource scopes
    anonymous_scope       = "read-public", -- keycloak scope to allow anonymous
    client_id             = "nginx",
    client_secret         = "00000000-0000-0000-0000-000000000000",
    endpoint              = "http://localhost:8080/auth",
    realm                 = "master",
}

-- ngx test harness
local ngx = {}
ngx["var"] = {
    keycloak_anonymous_policy_mode = "permissive", -- enforcing, permissive, disabled : enforcing requires anonymous_scope to be in the resource scopes
    keycloak_anonymous_scope       = "read-public", -- keycloak scope to allow anonymous
    keycloak_client_id             = "nginx",
    keycloak_client_secret         = "00000000-0000-0000-0000-000000000000",
    keycloak_endpoint              = "http://localhost:8080/auth",
    keycloak_realm                 = "master",
}

-- resty-env test harness
local r_env = {}
local envvars = {
    KEYCLOAK_ANONYMOUS_POLICY_MODE = "permissive", -- enforcing, permissive, disabled : enforcing requires anonymous_scope to be in the resource scopes
    KEYCLOAK_ANONYMOUS_SCOPE       = "read-public", -- keycloak scope to allow anonymous
    KEYCLOAK_CLIENT_ID             = "nginx",
    KEYCLOAK_CLIENT_SECRET         = "00000000-0000-0000-0000-000000000000",
    KEYCLOAK_ENDPOINT              = "http://localhost:8080/auth",
    KEYCLOAK_REALM                 = "master",
}
function r_env.get(k)
    return envvars[k]
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

-- Returns KeyCloak client configuration as a Lua table.
-- Pulls in all values from defaults (keycloak_default_config)
-- Overrides default values with ENV values where they are not default
-- Overrides default + ENV with Nginx "set" values where they are not default
-- Nginx "set" values are the highest priority, so admins can avoid having sensitive data in ENV
local function keycloak_get_config()
    local env_table = {}
    local set_table = {}

    -- get ENV values based on default config keys
    -- eg. keycloak_default_config["foo"] will look for ENV["KEYCLOAK_FOO"]
    -- eg. keycloak_default_config["foo"] will look for nginx.var.keycloak_foo
    for k,v in pairs(keycloak_default_config) do
        local env_key_name = "KEYCLOAK_" .. string.upper(k)
        local set_key_name = "keycloak_" .. k
        env_table[k] = r_env.get(env_key_name) or keycloak_default_config[k]
        set_table[k] = ngx.var[set_key_name] or keycloak_default_config[k]
    end
    return keycloak_merge_config(set_table, env_table, keycloak_default_config)
end

envvars["KEYCLOAK_CLIENT_SECRET"] = "envvars set"
ngx.var["keycloak_client_secret"] = "nginx set"

local foo = keycloak_get_config()
print(inspect(foo))
