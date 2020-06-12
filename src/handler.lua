local BasePlugin = require "kong.plugins.base_plugin"
local JwtOauthPlugin = BasePlugin:extend()
local cjson = require "cjson"
local jwt = require "resty.jwt"
local re_gmatch = ngx.re.gmatch
local ck = require "resty.cookie"

function JwtOauthPlugin:new()
  JwtOauthPlugin.super.new(self, "jwt-oauth")
end

local function retrieve_token(conf)
    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
    end
    local cookie,err = ck:new()
	if cookie then
		local jwt_cookie,err = cookie:get(conf.cookie_name)
		if jwt_cookie and jwt_cookie ~= "" then
            return jwt_cookie
		end
    end
    local args = kong.request.get_query_arg(conf.uri_name)
    if args then
        return args
    end
end

local function is_in_table(value,tb)
  for k,v in ipairs(tb) do
    if v == value then
	return true
	end
  end
  return false
end

local function do_auth(token,key,conf)
  local jwt_obj = jwt:verify(key,token)
  if jwt_obj.verified == false then
    return nil
  end
  if type(jwt_obj.payload.role) == 'string' then
    if is_in_table(jwt_obj.payload.role,conf.roles) then
	  return cjson.encode(jwt_obj)
	end
  end
  if type(jwt_obj.payload.role) == 'table' then
    for _,v in ipairs(jwt_obj.payload.role) do
	  if is_in_table(v,conf.roles) then
	    return cjson.encode(jwt_obj)
	  end
	end
  end
  return nil
end

function JwtOauthPlugin:access(conf)
  JwtOauthPlugin.super.access(self)
  public_key = {
[[-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----]],
[[-----BEGIN CERTIFICATE-----
MIIDGDCCAgACCQDgKF7gaJXblzANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJj
bjELMAkGA1UECAwCZnoxCzAJBgNVBAcMAmZ6MQswCQYDVQQKDAJuZDELMAkGA1UE
CwwCbmQxCzAJBgNVBAMMAm5kMB4XDTE5MDgzMDAzMjUzNFoXDTI5MDgyNzAzMjUz
NFowTjELMAkGA1UEBhMCY24xCzAJBgNVBAgMAmZ6MQswCQYDVQQHDAJmejELMAkG
A1UECgwCbmQxCzAJBgNVBAsMAm5kMQswCQYDVQQDDAJuZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL3JfNFnfYsCQJNM9qIV/w6SZpNdvUpkndqK4JAF
lBnXVY4Z8acvxuj0gzJYv+XgifBWiq1HMGoQwSa5ys6qiNjiMhV0T8+l2q/5NhxY
zttwvw087eB+kxfVlTAs6/8WR039uBdo8vmPCkPIvzENAhpV4Wx6cakEGh9NgVIB
bbxneUQEOMSYlfl09Uo+wGGkpyF/gtIcjeR7rgjFo/NbR1AVJQWfjPJU1sIZD6Fp
U0OMxTk7OgWdaPrx0eTSBNRpqToTlsg07w3MocNE4Zt4UJFi9+vq8TcFv9Fk5MRG
ZW1Ai5KT1ysp6djdISxhmjJPIM7zHmC73sj/yzUjfo/H3p0CAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEABpO+JT4owKQNpoFDNRlArhEfOgOoLqVk3Yagsz4dGNFwJLz9
9000NOXBK6vGzuFuafVtdipyLFJYYWrUumeCnMpLuw7+hOG1+JVW07OdQ3M0lqEt
L2WRtsvXDRODnp5v8RWvPcNrEHn2JtH/Cvfy3ZDKTXPNNQB2f5f7A/jRbNzYMzI4
3Tin+K9iSxGCZp+vAFG5wg2ahA2YbamEjk+yBCvBaNYkaAHDtmczQF42dYq/gjOy
p5sYgp+k0sq/poR2hdrKZDklK0kXfSb9bjPucGjxyvxtRW1NmnpvB7dtW5LBCwM5
Qi7vM4wNj3GCNs+LnbxWWRO+PKoA1KDblfgJbg==
-----END CERTIFICATE-----]]}
  local jwt_token,err = retrieve_token(conf)
  if err then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred in retrieve_token" })
  end

  for _,v in ipairs(public_key) do
	local auth_ok,err = do_auth(jwt_token,v,conf)
	if auth_ok then
		kong.log.err(auth_ok)
		return
	end
  end
  return kong.response.exit(401, { message = "auth failed" })
end

return JwtOauthPlugin
