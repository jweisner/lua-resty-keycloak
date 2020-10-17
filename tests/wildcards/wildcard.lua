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

    -- create an array of asterixes in the pattern
    local stars = {}
    local i = 0
    while true do
        i = string.find(test, '*', i+1)
        if i ==nil then break end
        table.insert(stars,i)
    end

end

local test_subjects = {
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
