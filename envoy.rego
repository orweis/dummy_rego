# Envoy ext_authz demo policy (Rego v1, requires OPA 1.0+)
# ---------------------------------------------------------
#
# WARNING: DEMO ONLY - NOT SAFE FOR PRODUCTION.
# The second rule below grants full access to anyone who sends the literal
# header `Authorization: Basic charlie`. That is a static, publicly known
# value, not real authentication. It is kept only to preserve the original
# behavior of this example; do not deploy it as-is.
#
# Decision: `data.envoy.http.public.allow` (boolean, default false).
#
# Input: the Envoy External Authorization CheckRequest, of which this policy
# reads only:
#
#	* input.attributes.request.http.method
#	* input.attributes.request.http.path     (includes any query string)
#	* input.attributes.request.http.headers.authorization
#
# Anything missing or not matching is denied.
#
# References:
#
#	* Rego: https://www.openpolicyagent.org/docs/latest/policy-language/
#	* Envoy ext_authz: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto

package envoy.http.public

# Deny by default: if no rule below matches, `allow` is false.
default allow := false

# Public access: GET on exactly "/". The path is compared verbatim, so a
# request such as "/?x=1" is denied (fails closed).
allow if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path == "/"
}

# INSECURE DEMO RULE: full access (any method, any path) for the literal
# credential "Basic charlie". The comparison is exact and case-sensitive.
allow if {
	input.attributes.request.http.headers.authorization == "Basic charlie"
}
