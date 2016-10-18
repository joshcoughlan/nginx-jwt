local jwt = require "resty.jwt"
local cjson = require "cjson"
local basexx = require "basexx"
local secret = os.getenv("JWT_SECRET")
local jwtcookie = os.getenv("JWT_COOKIE")

assert(secret ~= nil, "Environment variable JWT_SECRET not set")

if os.getenv("JWT_SECRET_IS_BASE64_ENCODED") == 'true' then
    -- convert from URL-safe Base64 to Base64
    local r = #secret % 4
    if r == 2 then
        secret = secret .. "=="
    elseif r == 3 then
        secret = secret .. "="
    end
    secret = string.gsub(secret, "-", "+")
    secret = string.gsub(secret, "_", "/")

    -- convert from Base64 to UTF-8 string
    secret = basexx.from_base64(secret)
end

local M = {}

function M.auth(claim_specs)
    -- require Authorization request header
    local auth_header = ngx.var.http_Authorization
    local auth_cookie = ngx.var["cookie_" .. jwtcookie]
    local token

    if auth_header == nil and auth_cookie == nil then
        ngx.log(ngx.WARN, "No Authorization header or cookie")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    elseif auth_header == nil and auth_cookie ~= nil then
        token = auth_cookie
    elseif auth_header ~= nil and auth_cookie == nil then
        _, _, token = string.find(auth_header, "Bearer%s+(.+)")
        auth_header = auth_cookie
    end

    -- require Bearer token

    if token == nil then
        ngx.log(ngx.WARN, "Missing token")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.DEBUG, "Token: " .. token)

    -- require valid JWT
    local jwt_obj = jwt:verify(secret, token, claim_specs)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.DEBUG, "JWT: " .. cjson.encode(jwt_obj))
    
    -- write the X-Auth-UserId header
    ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
end

function M.table_contains(table, item)
    for _, value in pairs(table) do
        if value == item then return true end
    end
    return false
end

return M
