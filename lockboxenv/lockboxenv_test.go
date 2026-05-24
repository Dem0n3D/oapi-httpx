package lockboxenv

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestLoadSetsMissingValues(t *testing.T) {
	t.Setenv("EXISTING_VALUE", "from-env")
	t.Cleanup(func() {
		_ = os.Unsetenv("SIMPLE")
		_ = os.Unsetenv("BINARY")
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lockbox/v1/secrets/secret-id/payload" {
			t.Fatalf("path = %q, want payload path", r.URL.Path)
		}
		if got := r.URL.Query().Get("versionId"); got != "version-id" {
			t.Fatalf("versionId = %q, want %q", got, "version-id")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer iam-token" {
			t.Fatalf("Authorization = %q, want Bearer token", got)
		}

		_, _ = w.Write([]byte(`{
			"versionId": "version-id",
			"entries": [
				{"key": "SIMPLE", "textValue": "value"},
				{"key": "BINARY", "binaryValue": "` + base64.StdEncoding.EncodeToString([]byte("from-binary")) + `"},
				{"key": "EXISTING_VALUE", "textValue": "from-lockbox"}
			]
		}`))
	}))
	defer server.Close()

	result, err := Load(context.Background(), Options{
		SecretID:        "secret-id",
		SecretVersionID: "version-id",
		YCIAMToken:      "iam-token",
		PayloadEndpoint: server.URL,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := os.Getenv("SIMPLE"); got != "value" {
		t.Fatalf("SIMPLE = %q, want %q", got, "value")
	}
	if got := os.Getenv("BINARY"); got != "from-binary" {
		t.Fatalf("BINARY = %q, want %q", got, "from-binary")
	}
	if got := os.Getenv("EXISTING_VALUE"); got != "from-env" {
		t.Fatalf("EXISTING_VALUE = %q, want %q", got, "from-env")
	}
	if !reflect.DeepEqual(result.LoadedKeys, []string{"SIMPLE", "BINARY"}) {
		t.Fatalf("LoadedKeys = %#v, want SIMPLE/BINARY", result.LoadedKeys)
	}
	if !reflect.DeepEqual(result.SkippedKeys, []string{"EXISTING_VALUE"}) {
		t.Fatalf("SkippedKeys = %#v, want EXISTING_VALUE", result.SkippedKeys)
	}
}

func TestLoadCanOverwriteExistingValues(t *testing.T) {
	t.Setenv("EXISTING_VALUE", "from-env")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"entries": [
				{"key": "EXISTING_VALUE", "textValue": "from-lockbox"}
			]
		}`))
	}))
	defer server.Close()

	result, err := Load(context.Background(), Options{
		SecretID:          "secret-id",
		YCIAMToken:        "iam-token",
		PayloadEndpoint:   server.URL,
		OverwriteExisting: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := os.Getenv("EXISTING_VALUE"); got != "from-lockbox" {
		t.Fatalf("EXISTING_VALUE = %q, want %q", got, "from-lockbox")
	}
	if !reflect.DeepEqual(result.LoadedKeys, []string{"EXISTING_VALUE"}) {
		t.Fatalf("LoadedKeys = %#v, want EXISTING_VALUE", result.LoadedKeys)
	}
}

func TestLoadUsesMetadataToken(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Unsetenv("FROM_METADATA")
	})

	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Fatalf("Metadata-Flavor = %q, want Google", got)
		}

		_, _ = w.Write([]byte(`{"access_token":"metadata-token"}`))
	}))
	defer metadataServer.Close()

	payloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer metadata-token" {
			t.Fatalf("Authorization = %q, want metadata token", got)
		}

		_, _ = w.Write([]byte(`{"entries":[{"key":"FROM_METADATA","textValue":"ok"}]}`))
	}))
	defer payloadServer.Close()

	if _, err := Load(context.Background(), Options{
		SecretID:              "secret-id",
		PayloadEndpoint:       payloadServer.URL,
		MetadataTokenEndpoint: metadataServer.URL,
	}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := os.Getenv("FROM_METADATA"); got != "ok" {
		t.Fatalf("FROM_METADATA = %q, want %q", got, "ok")
	}
}

func TestLoadRejectsVersionWithoutSecretID(t *testing.T) {
	if _, err := Load(context.Background(), Options{SecretVersionID: "version-id"}); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func TestLoadRejectsInvalidEntryKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"key":"INVALID-KEY","textValue":"value"}]}`))
	}))
	defer server.Close()

	if _, err := Load(context.Background(), Options{
		SecretID:        "secret-id",
		YCIAMToken:      "iam-token",
		PayloadEndpoint: server.URL,
	}); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func TestLoadFromEnvironmentNoopsWithoutSecretID(t *testing.T) {
	t.Setenv(SecretIDEnvVar, "")
	t.Setenv(SecretVersionIDEnvVar, "")

	result, err := LoadFromEnvironment(context.Background())
	if err != nil {
		t.Fatalf("LoadFromEnvironment: %v", err)
	}
	if len(result.LoadedKeys) != 0 || len(result.SkippedKeys) != 0 {
		t.Fatalf("result = %#v, want empty", result)
	}
}
