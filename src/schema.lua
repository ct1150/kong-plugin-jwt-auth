return {
  no_consumer = true,
  fields = {
    need_role = {type = "boolean", default = false},
    roles = {type = "array"},
    uri_name = {type = "string", default = "jwt"},
    cookie_name = {type = "string", default = "authToken"},
	single_device = {type = "boolean", default = false},
	redis_host = {type="string"},
	redis_port = {type="number", default = 6379},
	redis_pass = {type="string"},
	redis_db = {type="number"},
	redis_hash = {type="string"}
  }
}
