package security

import "testing"

func TestHasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		scopes        []string
		requiredScope string
		want          bool
	}{
		{
			name:          "empty required scope is allowed",
			scopes:        []string{"orders:read"},
			requiredScope: " ",
			want:          true,
		},
		{
			name:          "matches trimmed scope",
			scopes:        []string{" orders:read "},
			requiredScope: "orders:read",
			want:          true,
		},
		{
			name:          "returns false when scope is missing",
			scopes:        []string{"orders:write"},
			requiredScope: "orders:read",
			want:          false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := HasScope(tt.scopes, tt.requiredScope); got != tt.want {
				t.Fatalf("HasScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasRequiredScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		granted  []string
		required []string
		want     bool
	}{
		{
			name:     "empty required scopes are allowed",
			granted:  []string{"orders:read"},
			required: nil,
			want:     true,
		},
		{
			name:     "matches all required trimmed scopes",
			granted:  []string{" orders:read ", "orders:write"},
			required: []string{"orders:read", " orders:write "},
			want:     true,
		},
		{
			name:     "returns false when a required scope is missing",
			granted:  []string{"orders:read"},
			required: []string{"orders:read", "orders:write"},
			want:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := HasRequiredScopes(tt.granted, tt.required); got != tt.want {
				t.Fatalf("HasRequiredScopes() = %v, want %v", got, tt.want)
			}
		})
	}
}
