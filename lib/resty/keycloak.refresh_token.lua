
--[[
    Fetch a new access token from a refresh token

    refresh_token (string): a refresh token

    returns new token resource table or nil

    example return data:
    {
        access_token       = "access token as string",
        expires_in         = 300,
        refresh_token      = "refresh token as string",
        refresh_expires_in = 1800,
    }
]]
--[[
local function keycloak_refresh_token(refresh_token)
    assert(type(refresh_token) == "string")

    local config          = keycloak_config()
    local request_headers = {}
    local request_body    = {
        refresh_token = refresh_token,
        client_id     = config['client_id'],
        client_secret = config['client_secret'],
    }

    local res,err = keycloak_call_endpoint("openid", "token_endpoint", request_headers, request_body, {}, "POST")

    if err ~= nil then
        ngx.log(ngx.ERR, "Error refreshing access token: " .. err)
        return nil
    end

    assert(type(res) == "table", "Token endpoint returned invalid data for refresh token!")
end
]]