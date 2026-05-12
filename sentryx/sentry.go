package sentryx

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
)

type Config struct {
	DSN              string
	Environment      string
	Release          string
	EnableTracing    bool
	TracesSampleRate float64
}

func (c Config) Enabled() bool {
	return strings.TrimSpace(c.DSN) != ""
}

func (c Config) Validate() error {
	if c.TracesSampleRate < 0 || c.TracesSampleRate > 1 {
		return errors.New("SENTRY_TRACES_SAMPLE_RATE must be between 0 and 1")
	}

	return nil
}

type Client struct {
	enabled bool
}

type ErrorResponse interface {
	~struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
}

func Init(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if !cfg.Enabled() {
		return &Client{}, nil
	}

	if err := sentry.Init(sentry.ClientOptions{
		Dsn:              strings.TrimSpace(cfg.DSN),
		Environment:      strings.TrimSpace(cfg.Environment),
		Release:          strings.TrimSpace(cfg.Release),
		EnableTracing:    cfg.EnableTracing,
		TracesSampleRate: cfg.TracesSampleRate,
	}); err != nil {
		return nil, err
	}

	return &Client{enabled: true}, nil
}

func (c *Client) Enabled() bool {
	return c != nil && c.enabled
}

func (c *Client) CaptureException(err error) {
	if !c.Enabled() || err == nil {
		return
	}

	CaptureException(context.Background(), err)
}

func CaptureException(ctx context.Context, err error) {
	if err == nil {
		return
	}

	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		hub.CaptureException(err)
		return
	}

	sentry.CaptureException(err)
}

func InternalErrorResponse[T ErrorResponse](ctx context.Context, err error) T {
	CaptureException(ctx, err)

	return T{
		Error:            "internal_error",
		ErrorDescription: "internal server error",
	}
}

func (c *Client) RecoverAndFlush(timeout time.Duration) {
	if !c.Enabled() {
		return
	}

	err := recover()
	if err == nil {
		return
	}

	sentry.CurrentHub().Recover(err)
	c.Flush(timeout)
	panic(err)
}

func (c *Client) Flush(timeout time.Duration) bool {
	if !c.Enabled() {
		return true
	}

	return sentry.Flush(timeout)
}

func HTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	if !cfg.Enabled() {
		return nil
	}

	return sentryhttp.New(sentryhttp.Options{
		Repanic: true,
	}).Handle
}
