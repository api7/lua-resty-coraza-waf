-- Sends one HTTP/1.0 request (so the response is not chunked) over a cosocket and returns the response body.
local _M = {}

function _M.request(method, path, headers, body)
    local sock = ngx.socket.tcp()
    assert(sock:connect("127.0.0.1", tonumber(ngx.var.server_port)))
    local lines = { method .. " " .. path .. " HTTP/1.0", "Host: localhost",
                    "Connection: close" }
    for k, v in pairs(headers or {}) do
        lines[#lines + 1] = k .. ": " .. v
    end
    if body then
        lines[#lines + 1] = "Content-Length: " .. #body
    end
    assert(sock:send(table.concat(lines, "\r\n") .. "\r\n\r\n" .. (body or "")))
    local data = assert(sock:receive("*a"))
    sock:close()
    return data:match("\r\n\r\n(.*)$")
end

return _M
