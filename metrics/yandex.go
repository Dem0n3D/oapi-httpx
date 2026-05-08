package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultYandexMonitoringEndpoint = "https://monitoring.api.cloud.yandex.net"
	defaultYandexMetadataEndpoint   = "http://169.254.169.254"
)

type YandexOptions struct {
	FolderID         string
	Endpoint         string
	IAMToken         string
	MetadataEndpoint string
	RequestTimeout   time.Duration
	CommonLabels     map[string]string
}

type YandexExporter struct {
	folderID      string
	endpoint      string
	commonLabels  map[string]string
	tokenProvider tokenProvider
	httpClient    *http.Client
}

type tokenProvider interface {
	Token(ctx context.Context) (string, error)
}

func NewYandexExporter(options YandexOptions) (*YandexExporter, error) {
	folderID := strings.TrimSpace(options.FolderID)
	if folderID == "" {
		return nil, fmt.Errorf("yandex monitoring folder id is required")
	}

	endpoint := strings.TrimRight(strings.TrimSpace(options.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultYandexMonitoringEndpoint
	}

	requestTimeout := options.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 2 * time.Second
	}

	var provider tokenProvider
	if token := strings.TrimSpace(options.IAMToken); token != "" {
		provider = staticTokenProvider(token)
	} else {
		metadataEndpoint := strings.TrimRight(strings.TrimSpace(options.MetadataEndpoint), "/")
		if metadataEndpoint == "" {
			metadataEndpoint = defaultYandexMetadataEndpoint
		}
		provider = newMetadataTokenProvider(metadataEndpoint, &http.Client{Timeout: requestTimeout})
	}

	return &YandexExporter{
		folderID:      folderID,
		endpoint:      endpoint,
		commonLabels:  copyLabels(options.CommonLabels),
		tokenProvider: provider,
		httpClient:    &http.Client{Timeout: requestTimeout},
	}, nil
}

func (e *YandexExporter) NewCounter(name string) Counter {
	return yandexCounter{
		exporter: e,
		name:     name,
	}
}

type yandexCounter struct {
	exporter *YandexExporter
	name     string
}

func (c yandexCounter) Add(ctx context.Context, labels map[string]string, value float64) error {
	if value < 0 {
		return fmt.Errorf("yandex counter value must be non-negative")
	}

	return c.exporter.write(ctx, []yandexMetric{
		{
			Name:   c.name,
			Labels: copyLabels(labels),
			Type:   "COUNTER",
			Value:  value,
		},
	})
}

func (c yandexCounter) Inc(ctx context.Context, labels map[string]string) error {
	return c.Add(ctx, labels, 1)
}

func (e *YandexExporter) write(ctx context.Context, metrics []yandexMetric) error {
	token, err := e.tokenProvider.Token(ctx)
	if err != nil {
		return fmt.Errorf("get yandex monitoring token: %w", err)
	}

	requestBody := yandexWriteRequest{
		Labels:  e.commonLabels,
		Metrics: metrics,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal yandex monitoring request: %w", err)
	}

	writeURL, err := url.Parse(e.endpoint + "/monitoring/v2/data/write")
	if err != nil {
		return fmt.Errorf("parse yandex monitoring endpoint: %w", err)
	}
	query := writeURL.Query()
	query.Set("folderId", e.folderID)
	query.Set("service", "custom")
	writeURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, writeURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create yandex monitoring request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("write yandex monitoring metric: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("write yandex monitoring metric: status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	return nil
}

type yandexWriteRequest struct {
	Labels  map[string]string `json:"labels,omitempty"`
	Metrics []yandexMetric    `json:"metrics"`
}

type yandexMetric struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Type   string            `json:"type,omitempty"`
	Value  float64           `json:"value"`
}

type staticTokenProvider string

func (p staticTokenProvider) Token(context.Context) (string, error) {
	return string(p), nil
}

type metadataTokenProvider struct {
	endpoint   string
	httpClient *http.Client
	mu         sync.Mutex
	token      string
	expiresAt  time.Time
}

func newMetadataTokenProvider(endpoint string, httpClient *http.Client) *metadataTokenProvider {
	return &metadataTokenProvider{
		endpoint:   endpoint,
		httpClient: httpClient,
	}
}

func (p *metadataTokenProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && time.Now().Before(p.expiresAt.Add(-time.Minute)) {
		return p.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", fmt.Errorf("create metadata token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request metadata token: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("metadata token status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var tokenResponse metadataTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode metadata token: %w", err)
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return "", fmt.Errorf("metadata token response has empty access token")
	}

	expiresIn := time.Duration(tokenResponse.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}

	p.token = tokenResponse.AccessToken
	p.expiresAt = time.Now().Add(expiresIn)
	return p.token, nil
}

type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}
