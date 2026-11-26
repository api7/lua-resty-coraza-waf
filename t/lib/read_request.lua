-- The current request in the form eval takes, read as in the README example.
return function()
    local headers = {}
    for name, value in pairs(ngx.req.get_headers(100)) do
        if type(value) == "table" then
            for _, v in ipairs(value) do
                headers[#headers + 1] = { name, v }
            end
        else
            headers[#headers + 1] = { name, value }
        end
    end
    ngx.req.read_body()
    return {
        method = ngx.req.get_method(),
        uri = ngx.var.request_uri,
        protocol = ngx.var.server_protocol,
        client_ip = ngx.var.remote_addr,
        client_port = tonumber(ngx.var.remote_port),
        server_name = ngx.var.host,
        headers = headers,
        body = ngx.req.get_body_data(),
    }
end
