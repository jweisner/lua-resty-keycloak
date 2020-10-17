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
    -- ... replace all * with .*
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

for i,subject in ipairs(test_subjects) do
    print("Subject: "..subject)
    for k,test_pattern in ipairs(test_patterns) do
        local match_depth = keycloak_uri_path_match(subject, test_pattern)
        if match_depth == nil then
            print(test_pattern.. " no match")
        else
            print(test_pattern.." match at depth "..match_depth)
        end
    end
    print()
end
