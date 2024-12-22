package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/CAFxX/httpcompression"
	"github.com/VictoriaMetrics/metrics"
	"github.com/goccy/go-yaml"
	"github.com/itchyny/gojq"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	logLevel          = flag.String("log-level", "info", "logging level: debug, info, warn, error")
	tailscaledSocket  = flag.String("tailscaled-socket", "/var/run/tailscale/tailscaled.sock", "unix socket path of tailscaled")
	address           = flag.String("address", ":9924", "listen address")
	config            = flag.String("config", "config.yaml", "config file")
	exporseMetadata   = flag.Bool("expose-metadata", true, "expose metadata on self metrics endpoint")
	enableCompression = flag.Bool("enable-compression", true, "enable response compression")
)

func main() {
	flag.Parse()

	initLogger(*logLevel)

	cfg, err := loadConfig(*config)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info("loaded config", "config", *config)

	metrics.ExposeMetadata(*exporseMetadata)

	h, err := newHandler(cfg)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	if *enableCompression {
		compress, err := httpcompression.DefaultAdapter()
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		h = compress(h)
	}

	slog.Info("built handler with config, listening", "address", *address, "compression", *enableCompression)

	if err := http.ListenAndServe(*address, h); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

type Config struct {
	Modules map[string]*Module `yaml:"modules"`
}

type Module struct {
	Path    string `yaml:"path"`
	Source  string `yaml:"source"` // "localapi" or "publicapi"
	Filter  string `yaml:"filter"`
	Targets string `yaml:"targets"`
	Labels  string `yaml:"labels"`

	// only for source="publicapi"
	TailnetEnv           string `yaml:"tailnetEnv"`
	APIKeyEnv            string `yaml:"apiKeyEnv"`
	OAuthClientIDEnv     string `yaml:"oauthClientIDEnv"`
	OAuthClientSecretEnv string `yaml:"oauthClientSecretEnv"`
}

func strDefault(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

func (m *Module) buildExpression() (string, error) {
	filter := strDefault(m.Filter, ".")
	targets := strDefault(m.Targets, "[]")
	labels := strDefault(m.Labels, "{}")
	switch m.Source {
	case "localapi", "":
		return fmt.Sprintf(`
[
	[.Peer | to_entries[].value] +
	[.Self] |
	.[] | 
	%s |
	{
		targets: %s,
		labels: %s,
	}
]
		`, filter, targets, labels), nil
	case "publicapi":
		return fmt.Sprintf(`
[
	.devices[] |
	%s |
	{
		targets: %s,
		labels: %s,
	}
]
		`, filter, targets, labels), nil
	default:
		return "", fmt.Errorf("invalid source %s", m.Source)
	}
}

func (m *Module) compile() (*gojq.Code, error) {
	expr, err := m.buildExpression()
	if err != nil {
		return nil, err
	}
	query, err := gojq.Parse(expr)
	if err != nil {
		return nil, err
	}
	code, err := gojq.Compile(query)
	if err != nil {
		return nil, err
	}
	return code, nil
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func newHandler(cfg *Config) (http.Handler, error) {
	mux := http.NewServeMux()
	for name, mod := range cfg.Modules {
		code, err := mod.compile()
		if err != nil {
			return nil, err
		}
		var p string
		if strings.HasPrefix(mod.Path, "/") {
			p = mod.Path
		} else {
			p = path.Join("/", name)
		}
		var source string
		if mod.Source == "" {
			source = "localapi"
		} else {
			source = mod.Source
		}
		slog.Info("register handler for module", "name", name, "path", p, "source", source)
		var client apiClient
		switch source {
		case "localapi", "":
			client = &localapiClient{
				httpClient: httpUnixClient(*tailscaledSocket),
			}
		case "publicapi":
			var err error
			client, err = newPublicAPIClient(mod)
			if err != nil {
				return nil, fmt.Errorf("invalid module config for %s: %w", name, err)
			}
		}
		mux.HandleFunc("GET "+p, handler(code, client))
	}
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics.WriteProcessMetrics(w)
	})
	return mux, nil
}

func handler(code *gojq.Code, client apiClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		resp, err := client.retrieve(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		result, err := jq(ctx, code, resp)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if result == nil {
			slog.Error("no result")
			http.Error(w, "no result", http.StatusInternalServerError)
			return
		}
		sdResp, ok := result.([]any)
		if !ok {
			slog.Error("invalid filter result", "result", fmt.Sprintf("%v", result))
			http.Error(w, "invalid filter result", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(sdResp); err != nil {
			slog.Error(err.Error())
		}
	}
}

type apiClient interface {
	retrieve(ctx context.Context) (any, error)
}

type localapiClient struct {
	httpClient *http.Client
}

func (c *localapiClient) retrieve(ctx context.Context) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return status, nil
}

func jq(ctx context.Context, code *gojq.Code, v any) (any, error) {
	iter := code.RunWithContext(ctx, v)
	var result any
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			if err, ok := err.(*gojq.HaltError); ok && err.Value() == nil {
				break
			}
			return nil, err
		}
		result = v
	}
	return result, nil
}

func httpUnixClient(socketPath string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	return &http.Client{Transport: transport}
}

type publicapiClient struct {
	client  *http.Client
	baseURL string
	tailnet string
	apiKey  string
}

func newPublicAPIClient(m *Module) (*publicapiClient, error) {
	var (
		err     error
		tailnet string
	)

	if m.TailnetEnv == "" || os.Getenv(m.TailnetEnv) == "" {
		tailnet = "-"
	} else {
		tailnet, err = getEnv(m.TailnetEnv)
		if err != nil {
			return nil, err
		}
	}
	const baseURL = "https://api.tailscale.com"
	if m.APIKeyEnv != "" {
		apiKey, err := getEnv(m.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		return &publicapiClient{
			client:  &http.Client{},
			baseURL: baseURL,
			tailnet: tailnet,
			apiKey:  apiKey,
		}, nil
	} else if m.OAuthClientIDEnv != "" && m.OAuthClientSecretEnv != "" {
		oauthClientID, err := getEnv(m.OAuthClientIDEnv)
		if err != nil {
			return nil, err
		}
		oauthClientSecret, err := getEnv(m.OAuthClientSecretEnv)
		if err != nil {
			return nil, err
		}
		oauthCfg := clientcredentials.Config{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
			TokenURL:     baseURL + "/api/v2/oauth/token",
		}
		return &publicapiClient{
			client:  oauthCfg.Client(context.Background()),
			baseURL: baseURL,
			tailnet: tailnet,
		}, nil
	}

	return nil, errors.New("invalid config for publicapi")
}

func getEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is empty", key)
	}
	return v, nil
}

func (c *publicapiClient) retrieve(ctx context.Context) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+fmt.Sprintf("/api/v2/tailnet/%s/devices", c.tailnet), nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.SetBasicAuth(c.apiKey, "")
	}
	req.Header.Set("User-Agent", "prometheus-tailscalesd")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var v any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func initLogger(loglevel string) {
	slogLevel := slog.LevelInfo
	switch strings.ToLower(loglevel) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slogLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					source.File = filepath.Base(source.File)
				}
			}
			return a
		}},
	)))
}
