local BasePlugin = require "kong.plugins.base_plugin"
local JwtOauthPlugin = BasePlugin:extend()
local cjson = require "cjson"
local jwt = require "resty.jwt"
local re_gmatch = ngx.re.gmatch
local ck = require "resty.cookie"
local redis = require "resty.redis"

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
            return jwt_cookie["access_token"]
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
    kong.log.err(jwt_obj.reason)
    return nil
  end
  if conf.single_device then
	local red = redis:new()
	red:set_timeouts(2000, 2000, 2000) -- 2 sec
	local ok, err = red:connect(conf.redis_host, conf.redis_port)
	if not ok then
		kong.response.exit(500, { message = "can not connect to redis" })
		return nil
	end
    if conf.redis_pass then
	local res, err = red:auth(conf.redis_pass)
		if not res then
			kong.response.exit(500, { message = "failed to authenticate redis" })
			return nil
		end
	end
	if conf.redis_db then
		ok, err = red:select(conf.redis_db)
		if not ok then
			kong.log.err("failed to select redis_db")
			return nil
		end
	end
	local res, err = red:hmget(conf.redis_hash, "access-token-"..jwt_obj.payload.userId)
	if res then
	    if res ~= token then
		kong.response.exit(401, { message = "只能同时登录一个设备" })
		end
	end
	--set header
	kong.service.request.set_headers({
  ["X-User-Id"] = jwt_obj.payload.userId,
  ["X-Role-Code"] = kong.request.get_header('rolecode')
})
  end   
  if conf.need_role then
	  if type(jwt_obj.payload.role) == 'string' then
		if is_in_table(jwt_obj.payload.role,conf.roles) then
		  return jwt_obj.reason
		end
	  end
	  if type(jwt_obj.payload.role) == 'table' then
		for _,v in ipairs(jwt_obj.payload.role) do
		  if is_in_table(v,conf.roles) then
			return jwt_obj.reason
		  end
		end
	  end
  else
      return 'auth ok'
  end
end

function JwtOauthPlugin:access(conf)
  JwtOauthPlugin.super.access(self)
  if kong.request.get_method() == "OPTIONS" then
    return
  end
  if string.match(kong.request.get_path(),'^/.*/health$') then
    return
  end
  if string.match(kong.request.get_path(),'^/health$') then
    return
  end
  if string.match(kong.request.get_path(),'^/.*/swagger') then
    return
  end
  public_key = {
[[-----BEGIN CERTIFICATE-----
xxxx
-----END CERTIFICATE-----]],
[[-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----]],}
  local jwt_token,err = retrieve_token(conf)
  if err then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred in retrieve_token" })
  end

  for _,v in ipairs(public_key) do
	local auth_ok,err = do_auth(jwt_token,v,conf)
	if auth_ok then
		--kong.log.err(auth_ok)
		return
	end
  end
  return kong.response.exit(401, { message = "auth failed" })
end

return JwtOauthPlugin
