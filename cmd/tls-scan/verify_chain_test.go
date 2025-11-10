package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestVerifyChain_SelfRooted(t *testing.T) {
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	// Leaf signed by root
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, rootCert},
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	if err := verifyChain(cs, "example.com", roots); err != nil {
		t.Fatalf("verifyChain failed: %v", err)
	}

	// Wrong hostname should fail
	if err := verifyChain(cs, "not-example.com", roots); err == nil {
		t.Fatalf("verifyChain should fail on wrong DNSName")
	}

	// No roots should fail (can't chain to system in test)
	if err := verifyChain(cs, "example.com", nil); err == nil {
		t.Fatalf("verifyChain should fail without roots")
	}
}

// Sanity check split host/port default
func TestSplitHostPortDefault(t *testing.T) {
	h, p := splitHostPortDefault("example.com", 443)
	if h != "example.com" || p != "443" {
		t.Fatalf("unexpected: %s:%s", h, p)
	}
	h, p = splitHostPortDefault("example.com:8443", 443)
	if h != "example.com" || p != "8443" {
		t.Fatalf("unexpected: %s:%s", h, p)
	}
	_ = context.TODO() // keep lint happy on unused imports across files
}
