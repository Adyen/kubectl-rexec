package server

import (
	"net/http"
)

// verifiedFrontProxy reports whether the request arrived over a TLS connection
// presenting a client certificate that chains to the requestheader CA and whose
// common name is in the allowed-names list (an empty list allows any verified
// name). Only requests that satisfy this may be trusted to carry X-Remote-*
// identity headers used for impersonation.
func verifiedFrontProxy(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	if len(RequestHeaderAllowedNames) == 0 {
		return true
	}
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	for _, allowed := range RequestHeaderAllowedNames {
		if allowed == cn {
			return true
		}
	}
	return false
}
