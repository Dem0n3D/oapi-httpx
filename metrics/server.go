package metrics

import (
	"net/http"
	"time"
)

// Serve starts a small HTTP server for exposing metrics until ctxDone is closed.
func Serve(ctxDone <-chan struct{}, addr string, handler http.Handler) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctxDone
		_ = server.Close()
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
