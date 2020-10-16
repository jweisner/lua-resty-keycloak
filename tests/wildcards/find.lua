test    = "/*/bar/*"
subject = "/foo/bar/baz/"

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

-- create an array of asterisks in the pattern
local stars = {}
local i = 0
while true do
	i = string.find(test, '*', i+1)
	if i == nil then break end
	table.insert(stars,i)
end

local test_expanded = ''
