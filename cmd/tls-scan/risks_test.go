package main

import (
	"crypto/tls"
	"testing"
)

func TestProtocolRisks(t *testing.T) {
	cases := []struct {
		ver   uint16
		wantN int
		wantC string
	}{
		{tls.VersionTLS10, 1, "TLS_VERSION_OLD"},
		{tls.VersionTLS11, 1, "TLS_VERSION_OLD"},
		{tls.VersionTLS12, 0, ""},
		{tls.VersionTLS13, 0, ""},
	}
	for _, c := range cases {
		got := protocolRisks(c.ver)
		if len(got) != c.wantN {
			t.Fatalf("ver %s: want %d risks, got %d", tlsVersionString(c.ver), c.wantN, len(got))
		}
		if c.wantN == 1 && got[0].Code != c.wantC {
			t.Fatalf("ver %s: want code %s, got %s", tlsVersionString(c.ver), c.wantC, got[0].Code)
		}
	}
}

func TestCipherRisks(t *testing.T) {
	// Use known suite IDs that exist in Go's registry.
	// 0x000A = TLS_RSA_WITH_3DES_EDE_CBC_SHA (weak)
	weakID := uint16(0x000A)
	r := cipherRisks(weakID, tls.VersionTLS12)
	if len(r) == 0 || r[0].Code != "WEAK_CIPHER" {
		t.Fatalf("expected WEAK_CIPHER for 3DES, got %+v", r)
	}

	// TLS1.2 with CBC negotiated should warn
	// 0x002F = TLS_RSA_WITH_AES_128_CBC_SHA
	cbcID := uint16(0x002F)
	r = cipherRisks(cbcID, tls.VersionTLS12)
	if len(r) == 0 || r[0].Code != "CBC_ON_TLS12" {
		t.Fatalf("expected CBC_ON_TLS12, got %+v", r)
	}

	// TLS1.3 AEAD should be fine
	// 0x1301 = TLS_AES_128_GCM_SHA256
	okID := uint16(0x1301)
	r = cipherRisks(okID, tls.VersionTLS13)
	if len(r) != 0 {
		t.Fatalf("expected no risk for TLS1.3 AEAD, got %+v", r)
	}
}
