package security

import (
	"net/http"
	"strings"
)

func ExtractAccessToken(r *http.Request) (string, bool) {
	const bearerPrefix = "Bearer "

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return strings.TrimPrefix(authHeader, bearerPrefix), true
	}

	xAuthorizationHeader := r.Header.Get("X-Authorization")
	if strings.HasPrefix(xAuthorizationHeader, bearerPrefix) {
		return strings.TrimPrefix(xAuthorizationHeader, bearerPrefix), true
	}

	xAccessToken := strings.TrimSpace(r.Header.Get("X-Access-Token"))
	if xAccessToken != "" {
		return xAccessToken, true
	}

	return "", false
}
