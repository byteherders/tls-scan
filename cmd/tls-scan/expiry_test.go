package main

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestExpiryRisks(t *testing.T) {
	now := time.Now()
	leafSoon := &x509.Certificate{NotAfter: now.Add(5 * 24 * time.Hour)}
	leafWarn := &x509.Certificate{NotAfter: now.Add(20 * 24 * time.Hour)}
	leafOK := &x509.Certificate{NotAfter: now.Add(120 * 24 * time.Hour)}

	r := expiryRisks([]*x509.Certificate{leafSoon})
	if len(r) != 1 || r[0].Code != "EXPIRY_SOON_CRIT" {
		t.Fatalf("want critical expiry, got %+v", r)
	}

	r = expiryRisks([]*x509.Certificate{leafWarn})
	if len(r) != 1 || r[0].Code != "EXPIRY_SOON_WARN" {
		t.Fatalf("want warn expiry, got %+v", r)
	}

	r = expiryRisks([]*x509.Certificate{leafOK})
	if len(r) != 0 {
		t.Fatalf("want no expiry risk, got %+v", r)
	}

	r = expiryRisks(nil)
	if len(r) != 1 || r[0].Code != "NO_CERTS" {
		t.Fatalf("want NO_CERTS, got %+v", r)
	}
}
