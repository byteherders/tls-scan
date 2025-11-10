package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseHSTSMaxAge(t *testing.T) {
	if got := parseHSTSMaxAge("max-age=31536000; includeSubDomains; preload"); got != 31536000 {
		t.Fatalf("unexpected max-age: %d", got)
	}
	if got := parseHSTSMaxAge("MAX-AGE=100;"); got != 100 {
		t.Fatalf("case-insensitive parse failed")
	}
	if got := parseHSTSMaxAge("nope"); got != 0 {
		t.Fatalf("expected 0 for missing max-age, got %d", got)
	}
}

func TestProbeHSTS(t *testing.T) {
	// Start TLS server with HSTS
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// In tests we don't care about trust; skip verify
	tcfg := &tls.Config{InsecureSkipVerify: true}

	h, risks := probeHSTS(ctx, host, tcfg)
	if h == nil || !h.Present || h.MaxAge != 31536000 || !h.IncludeSubdomains || !h.Preload {
		t.Fatalf("unexpected HSTS parse: %+v", h)
	}
	if len(risks) != 0 {
		t.Fatalf("expected no HSTS risks, got %+v", risks)
	}
}

func TestProbeHSTS_Missing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no HSTS header
		w.WriteHeader(200)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tcfg := &tls.Config{InsecureSkipVerify: true}
	h, risks := probeHSTS(ctx, host, tcfg)
	if h == nil || h.Present {
		t.Fatalf("expected no HSTS")
	}
	found := false
	for _, r := range risks {
		if r.Code == "HSTS_MISSING" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HSTS_MISSING risk, got %+v", risks)
	}
}
