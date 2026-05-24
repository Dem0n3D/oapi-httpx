package lockboxenv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	SecretIDEnvVar        = "LOCKBOX_SECRET_ID_ENV"
	SecretVersionIDEnvVar = "LOCKBOX_SECRET_VERSION_ID_ENV"
	YCIAMTokenEnvVar      = "YC_IAM_TOKEN"

	DefaultPayloadEndpoint  = "https://payload.lockbox.api.cloud.yandex.net"
	DefaultMetadataEndpoint = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Options struct {
	SecretID        string
	SecretVersionID string
	YCIAMToken      string

	PayloadEndpoint       string
	MetadataTokenEndpoint string
	HTTPClient            *http.Client
	OverwriteExisting     bool
}

type Result struct {
	SecretID        string
	SecretVersionID string
	LoadedKeys      []string
	SkippedKeys     []string
}

type payloadResponse struct {
	VersionID string         `json:"versionId"`
	Entries   []payloadEntry `json:"entries"`
}

type payloadEntry struct {
	Key         string  `json:"key"`
	TextValue   *string `json:"textValue"`
	BinaryValue *string `json:"binaryValue"`
}

type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func LoadFromEnvironment(ctx context.Context) (*Result, error) {
	return Load(ctx, Options{
		SecretID:        strings.TrimSpace(os.Getenv(SecretIDEnvVar)),
		SecretVersionID: strings.TrimSpace(os.Getenv(SecretVersionIDEnvVar)),
		YCIAMToken:      strings.TrimSpace(os.Getenv(YCIAMTokenEnvVar)),
	})
}

func Load(ctx context.Context, options Options) (*Result, error) {
	options = options.withDefaults()

	if options.SecretID == "" {
		if options.SecretVersionID != "" {
			return nil, fmt.Errorf("%s is set but %s is empty", SecretVersionIDEnvVar, SecretIDEnvVar)
		}

		return &Result{}, nil
	}

	token, err := getYCIAMToken(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("load lockbox env: %w", err)
	}

	payload, err := getPayload(ctx, options, token)
	if err != nil {
		return nil, fmt.Errorf("load lockbox env: %w", err)
	}

	result := &Result{
		SecretID:        options.SecretID,
		SecretVersionID: payload.VersionID,
	}

	for _, entry := range payload.Entries {
		key := strings.TrimSpace(entry.Key)
		if !envKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("load lockbox env: invalid entry key %q", entry.Key)
		}

		if !options.OverwriteExisting {
			if _, exists := os.LookupEnv(key); exists {
				result.SkippedKeys = append(result.SkippedKeys, key)
				continue
			}
		}

		value, err := entryValue(entry)
		if err != nil {
			return nil, fmt.Errorf("load lockbox env: entry %s: %w", key, err)
		}

		if err := os.Setenv(key, value); err != nil {
			return nil, fmt.Errorf("load lockbox env: set env %s: %w", key, err)
		}
		result.LoadedKeys = append(result.LoadedKeys, key)
	}

	return result, nil
}

func (o Options) withDefaults() Options {
	o.SecretID = strings.TrimSpace(o.SecretID)
	o.SecretVersionID = strings.TrimSpace(o.SecretVersionID)
	o.YCIAMToken = strings.TrimSpace(o.YCIAMToken)

	if o.PayloadEndpoint == "" {
		o.PayloadEndpoint = DefaultPayloadEndpoint
	}
	if o.MetadataTokenEndpoint == "" {
		o.MetadataTokenEndpoint = DefaultMetadataEndpoint
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}

	return o
}

func getYCIAMToken(ctx context.Context, options Options) (string, error) {
	if options.YCIAMToken != "" {
		return options.YCIAMToken, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, options.MetadataTokenEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create metadata token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	var tokenResponse metadataTokenResponse
	if err := doJSONRequest(options.HTTPClient, req, &tokenResponse); err != nil {
		return "", fmt.Errorf("get metadata token: %w", err)
	}

	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return "", errors.New("metadata token response has empty access_token")
	}

	return tokenResponse.AccessToken, nil
}

func getPayload(ctx context.Context, options Options, token string) (*payloadResponse, error) {
	payloadURL, err := url.JoinPath(options.PayloadEndpoint, "lockbox/v1/secrets", options.SecretID, "payload")
	if err != nil {
		return nil, fmt.Errorf("build payload URL: %w", err)
	}

	if options.SecretVersionID != "" {
		parsedURL, err := url.Parse(payloadURL)
		if err != nil {
			return nil, fmt.Errorf("parse payload URL: %w", err)
		}
		query := parsedURL.Query()
		query.Set("versionId", options.SecretVersionID)
		parsedURL.RawQuery = query.Encode()
		payloadURL = parsedURL.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, payloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create payload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	var payload payloadResponse
	if err := doJSONRequest(options.HTTPClient, req, &payload); err != nil {
		return nil, fmt.Errorf("get secret payload: %w", err)
	}

	return &payload, nil
}

func doJSONRequest(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func entryValue(entry payloadEntry) (string, error) {
	switch {
	case entry.TextValue != nil:
		return *entry.TextValue, nil
	case entry.BinaryValue != nil:
		value, err := base64.StdEncoding.DecodeString(*entry.BinaryValue)
		if err != nil {
			return "", fmt.Errorf("decode binaryValue: %w", err)
		}
		return string(value), nil
	default:
		return "", errors.New("missing textValue or binaryValue")
	}
}
