-- directives of the tests: the embedded CRS in DetectionOnly mode
local _M = {}

function _M.directives(extra)
    return table.concat({
        "Include @coraza.conf-recommended",
        "Include @crs-setup.conf.example",
        "Include @owasp_crs/*.conf",
        extra or "",
        "SecRuleEngine DetectionOnly",
    }, "\n")
end

return _M
