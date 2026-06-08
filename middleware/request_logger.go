package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

type RequestLoggerOptions struct {
	BasePath  string
	SkipPaths []string
	Writer    io.Writer
}

func RequestLogger(options RequestLoggerOptions) func(http.Handler) http.Handler {
	writer := options.Writer
	if writer == nil {
		writer = os.Stdout
	}

	basePath := NormalizeBasePath(options.BasePath)
	skipPaths := make(map[string]struct{}, len(options.SkipPaths))
	for _, path := range options.SkipPaths {
		skipPaths[endpointPath(basePath, path)] = struct{}{}
	}
	logger := &jsonRequestLogger{
		writer: writer,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startedAt := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			logEntry := &jsonRequestLogEntry{
				logger:  logger,
				request: r,
			}

			next.ServeHTTP(ww, chimiddleware.WithLogEntry(r, logEntry))

			if _, ok := skipPaths[r.URL.Path]; ok {
				return
			}

			entry := httpRequestLog{
				Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
				Level:        "info",
				Message:      "http request",
				RequestID:    chimiddleware.GetReqID(r.Context()),
				Method:       r.Method,
				Path:         r.URL.Path,
				Query:        r.URL.RawQuery,
				Proto:        r.Proto,
				Status:       ww.Status(),
				BytesWritten: ww.BytesWritten(),
				DurationMS:   float64(time.Since(startedAt).Microseconds()) / 1000,
				RemoteAddr:   r.RemoteAddr,
				UserAgent:    r.UserAgent(),
			}

			logger.write(entry)
		})
	}
}

type jsonRequestLogger struct {
	writer io.Writer
	mu     sync.Mutex
}

func (l *jsonRequestLogger) write(entry any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	_ = json.NewEncoder(l.writer).Encode(entry)
}

type jsonRequestLogEntry struct {
	logger  *jsonRequestLogger
	request *http.Request
}

func (e *jsonRequestLogEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ interface{}) {
}

func (e *jsonRequestLogEntry) Panic(v interface{}, stack []byte) {
	r := e.request
	e.logger.write(httpRequestPanicLog{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Level:      "error",
		Message:    "http panic",
		RequestID:  chimiddleware.GetReqID(r.Context()),
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Proto:      r.Proto,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Panic:      fmt.Sprint(v),
		Stack:      string(stack),
	})
}

type httpRequestLog struct {
	Timestamp    string  `json:"timestamp"`
	Level        string  `json:"level"`
	Message      string  `json:"message"`
	RequestID    string  `json:"request_id,omitempty"`
	Method       string  `json:"method"`
	Path         string  `json:"path"`
	Query        string  `json:"query,omitempty"`
	Proto        string  `json:"proto"`
	Status       int     `json:"status"`
	BytesWritten int     `json:"bytes_written"`
	DurationMS   float64 `json:"duration_ms"`
	RemoteAddr   string  `json:"remote_addr,omitempty"`
	UserAgent    string  `json:"user_agent,omitempty"`
}

type httpRequestPanicLog struct {
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id,omitempty"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Query      string `json:"query,omitempty"`
	Proto      string `json:"proto"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Panic      string `json:"panic"`
	Stack      string `json:"stack"`
}

func endpointPath(basePath string, path string) string {
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	if basePath == "" {
		return path
	}

	return basePath + path
}
