return {
  no_consumer = true,
  fields = {
    roles = {type = "array", require = true},
    uri_name = {type = "string", default = "jwt"},
    cookie_name = {type = "string", default = "jwt"}
  }
}
