package sentryx

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
)

func TestConfigEnabled(t *testing.T) {
	testCases := []struct {
		name string
		dsn  string
		want bool
	}{
		{name: "empty", want: false},
		{name: "spaces", dsn: "   ", want: false},
		{name: "set", dsn: "https://public@example.invalid/1", want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Config{DSN: tc.dsn}).Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestConfigValidateTracesSampleRate(t *testing.T) {
	testCases := []struct {
		name      string
		rate      float64
		wantError bool
	}{
		{name: "zero", rate: 0},
		{name: "one", rate: 1},
		{name: "negative", rate: -0.1, wantError: true},
		{name: "above one", rate: 1.1, wantError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Config{TracesSampleRate: tc.rate}).Validate()
			if (err != nil) != tc.wantError {
				t.Fatalf("Validate() error = %v, wantError %t", err, tc.wantError)
			}
		})
	}
}

func TestCaptureExceptionUsesHubFromContext(t *testing.T) {
	transport := &recordingTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:       "https://public@example.invalid/1",
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	hub := sentry.NewHub(client, sentry.NewScope())
	ctx := sentry.SetHubOnContext(context.Background(), hub)

	CaptureException(ctx, errors.New("boom"))

	if got := transport.Len(); got != 1 {
		t.Fatalf("captured events = %d, want 1", got)
	}
}

func TestCaptureExceptionIgnoresNilError(t *testing.T) {
	CaptureException(context.Background(), nil)
}

type recordingTransport struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (t *recordingTransport) Flush(time.Duration) bool {
	return true
}

func (t *recordingTransport) FlushWithContext(context.Context) bool {
	return true
}

func (t *recordingTransport) Configure(sentry.ClientOptions) {}

func (t *recordingTransport) SendEvent(event *sentry.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.events = append(t.events, event)
}

func (t *recordingTransport) Close() {}

func (t *recordingTransport) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.events)
}
