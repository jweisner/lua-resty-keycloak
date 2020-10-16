function dumpTable(table, depth)
    local depth = depth or 0
    local debug_out = ""

    for k,v in pairs(table) do
        if (type(v) == "table") then
            debug_out = debug_out .. string.rep("  ", depth) .. k .. ":" .. "\n"
            dumpTable(v, depth+1)
        else
            debug_out = debug_out .. string.rep("  ", depth) .. k .. ": " .. v .. "\n"
        end
    end

    return debug_out
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
    if string.find(test, '*') == nil then
        return nil
    end

    -- shortcut "whole site" glob
    if test == '/*' then
        return 1
    end

    -- create an array of asterixes in the pattern
    local stars = {}
    local i = 0
    while true do
        i = string.find(test, '*', i+1)
        if i ==nil then break end
        table.insert(stars,i)
    end

end

local subjects = {
    '/',
    '/about.html',
    '/about/',
    '/about/index.html',
    '/groupone/',
    '/groupone/about/',
    '/groupone/secrets/',
    '/groupone/secrets/passwords/',
    '/groupone/secrets/phonenumbers/',
    '/grouptwo/',
    '/grouptwo/about/',
    '/grouptwo/secrets/',
    '/grouptwo/secrets/passwords/',
    '/grouptwo/secrets/phonenumbers/',
}

local test_patterns = {
    '/',
    '/*',
    '/about*/',
    '/about/',
    '/about/*',
    '/groupone/',
    '/groupone/*',
    '/groupone/about/',
    '/groupone/about/*',
    '/groupone/secrets/*',
    '/grouptwo/',
    '/grouptwo/*',
    '/grouptwo/about/',
    '/grouptwo/about/*',
    '/grouptwo/secrets/*',
    '/*/about/*',
    '/*/secrets/*',
}
