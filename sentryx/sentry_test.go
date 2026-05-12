package sentryx

import "testing"

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
