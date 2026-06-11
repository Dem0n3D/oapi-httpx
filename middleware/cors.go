package middleware

import (
	"net/http"
	"os"
	"strings"
)

const corsAllowedOriginsEnv = "CORS_ALLOWED_ORIGINS"

var defaultAllowedOrigins = []string{
	"http://localhost:3000",
	"http://localhost:4173",
	"http://localhost:5173",
	"http://127.0.0.1:3000",
	"http://127.0.0.1:4173",
	"http://127.0.0.1:5173",
}

func CORS(next http.Handler) http.Handler {
	allowedOrigins := parseAllowedOrigins(os.Getenv(corsAllowedOriginsEnv))
	if len(allowedOrigins) == 0 {
		allowedOrigins = defaultAllowedOrigins
	}
	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	allowAnyOrigin := false
	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAnyOrigin = true
			continue
		}
		allowedOriginSet[origin] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			if allowAnyOrigin || isOriginAllowed(origin, allowedOriginSet) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Origin, X-Access-Token, X-Authorization, X-Requested-With")
				w.Header().Set("Access-Control-Expose-Headers", "Authorization, Content-Type, X-Access-Token")
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func parseAllowedOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		origin := normalizeOrigin(part)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}

	return origins
}

func normalizeOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "*" {
		return origin
	}

	return strings.TrimRight(origin, "/")
}

func isOriginAllowed(origin string, allowed map[string]struct{}) bool {
	_, ok := allowed[normalizeOrigin(origin)]
	return ok
}
