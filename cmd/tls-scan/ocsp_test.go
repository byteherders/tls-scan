package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func makeCert(t *testing.T, tmpl, parent *x509.Certificate, pub *rsa.PublicKey, priv *rsa.PrivateKey) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestParseOCSP_GoodAndRevoked(t *testing.T) {
	// Generate issuer (CA) key/cert
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	issuerCert := makeCert(t, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)

	// Leaf
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	leafCert := makeCert(t, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)

	// Good OCSP response
	goodResp, err := ocsp.CreateResponse(issuerCert, leafCert, ocsp.Response{
		Status:       ocsp.Good,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		SerialNumber: leafCert.SerialNumber,
	}, issuerKey)
	if err != nil {
		t.Fatalf("CreateResponse good: %v", err)
	}

	// Revoked OCSP response
	revResp, err := ocsp.CreateResponse(issuerCert, leafCert, ocsp.Response{
		Status:       ocsp.Revoked,
		RevokedAt:    time.Now().Add(-time.Hour),
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		SerialNumber: leafCert.SerialNumber,
		RevocationReason: ocsp.Unspecified,
	}, issuerKey)
	if err != nil {
		t.Fatalf("CreateResponse revoked: %v", err)
	}

	// Feed into parseOCSP via a fake tls.ConnectionState
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, issuerCert},
		OCSPResponse:     goodResp,
	}
	info := parseOCSP(cs)
	if info.Status != "good" || info.NextUpdate == nil {
		t.Fatalf("expected good OCSP, got %+v", info)
	}

	cs.OCSPResponse = revResp
	info = parseOCSP(cs)
	if info.Status != "revoked" || info.RevokedAt == nil {
		t.Fatalf("expected revoked OCSP, got %+v", info)
	}
	_ = crypto.SHA256 // silence staticcheck about unused imports if it gets clever
}
