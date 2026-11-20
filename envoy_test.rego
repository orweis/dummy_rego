package envoy.http.public_test

import data.envoy.http.public

# Build an Envoy ext_authz style input.
req(method, path) := {"attributes": {"request": {"http": {"method": method, "path": path}}}}

req_auth(method, path, auth) := {"attributes": {"request": {"http": {
	"method": method,
	"path": path,
	"headers": {"authorization": auth},
}}}}

# --- public rule ---

test_get_root_allowed if {
	public.allow with input as req("GET", "/")
}

test_get_other_path_denied if {
	not public.allow with input as req("GET", "/admin")
}

test_get_root_with_query_denied if {
	not public.allow with input as req("GET", "/?probe=1")
}

test_double_slash_denied if {
	not public.allow with input as req("GET", "//")
}

test_post_root_denied if {
	not public.allow with input as req("POST", "/")
}

test_lowercase_method_denied if {
	not public.allow with input as req("get", "/")
}

test_other_methods_on_root_denied if {
	every m in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
		not public.allow with input as req(m, "/")
	}
}

# --- default deny ---

test_empty_input_denied if {
	not public.allow with input as {}
}

test_missing_http_attributes_denied if {
	not public.allow with input as {"attributes": {"request": {}}}
}

test_default_is_false if {
	public.allow == false with input as {}
}

# --- demo credential rule (pins existing insecure behavior) ---

test_demo_credential_allows_any_method_and_path if {
	public.allow with input as req_auth("DELETE", "/anything/at/all", "Basic charlie")
}

test_demo_credential_with_query_allowed if {
	public.allow with input as req_auth("POST", "/?x=1", "Basic charlie")
}

test_wrong_credential_denied if {
	not public.allow with input as req_auth("POST", "/", "Basic dave")
}

test_credential_is_case_sensitive if {
	not public.allow with input as req_auth("POST", "/", "basic charlie")
	not public.allow with input as req_auth("POST", "/", "Basic Charlie")
}

test_credential_no_trailing_whitespace_match if {
	not public.allow with input as req_auth("POST", "/", "Basic charlie ")
}

test_bearer_scheme_denied if {
	not public.allow with input as req_auth("POST", "/", "Bearer charlie")
}

test_empty_credential_denied if {
	not public.allow with input as req_auth("POST", "/", "")
}

test_wrong_credential_does_not_block_public_rule if {
	public.allow with input as req_auth("GET", "/", "Basic dave")
}
