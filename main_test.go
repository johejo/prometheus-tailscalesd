package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test(t *testing.T) {
	t.Log("this test requires tailscaled and node_exporter on port 9100")

	cfg, err := loadConfig("./testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	h, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/node-exporter", nil)
	h.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("invalid status code %d", res.StatusCode)
	}

	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("response should be json but %s", ct)
	}

	var resp []*httpSD
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	for _, sd := range resp {
		for _, target := range sd.Targets {
			if target == "" {
				t.Error("target should not be empty")
			}
			if !strings.HasSuffix(target, ":9100") {
				t.Error("target should have node_exporter port as suffix")
			}
		}
		if sd.Labels["__meta_tailscale_device_id"] == "" {
			t.Error("label __meta_tailscale_device_id should not be empty")
		}
		if sd.Labels["__meta_tailscale_device_dns_name"] == "" {
			t.Error("label __meta_tailscale_device_dns_name should not be empty")
		}
		if sd.Labels["__meta_tailscale_device_ipv4"] == "" {
			t.Error("label __meta_tailscale_device_ipv4 should not be empty")
		}
	}
}

type httpSD struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}
