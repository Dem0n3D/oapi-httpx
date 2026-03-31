package requestctx

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func MetadataMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithClientIP(r.Context(), ExtractClientIP(r))
		ctx = WithUserAgent(ctx, r.UserAgent())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ExtractClientIP(r *http.Request) string {
	for _, headerName := range []string{"X-Forwarded-For", "X-Real-IP"} {
		headerValue := strings.TrimSpace(r.Header.Get(headerName))
		if headerValue == "" {
			continue
		}

		if headerName == "X-Forwarded-For" {
			headerValue = strings.TrimSpace(strings.Split(headerValue, ",")[0])
		}

		if addr, err := netip.ParseAddr(headerValue); err == nil {
			return addr.String()
		}
	}

	hostPort := strings.TrimSpace(r.RemoteAddr)
	if hostPort == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err == nil {
		return host
	}

	if addr, err := netip.ParseAddr(hostPort); err == nil {
		return addr.String()
	}

	return hostPort
}
