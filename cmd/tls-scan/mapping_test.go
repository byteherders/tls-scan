package main

import (
	"crypto/tls"
	"fmt"
	"testing"
)

func TestTLSVersionString(t *testing.T) {
	cases := []uint16{
		tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13, 0x9999,
	}
	for _, v := range cases {
		s := tlsVersionString(v)
		if s == "" {
			t.Fatalf("empty string for version %#x", v)
		}
	}
}

func TestCipherSuiteString_NotEmpty(t *testing.T) {
	ids := []uint16{0x002F, 0x1301, 0xC02F, 0x000A, 0x9999}
	for _, id := range ids {
		s := cipherSuiteString(id)
		if s == "" {
			t.Fatalf("empty name for suite %#x", id)
		}
	}
}

func TestGradeResultBands(t *testing.T) {
	loadPolicy("") // defaults
	r := []Risk{
		{Code: "TLS_VERSION_OLD"},
		{Code: "WEAK_CIPHER"},
	}
	g := gradeResult(r)
	if g < 1 || g > 5 {
		t.Fatalf("grade out of range: %d", g)
	}

	// harmless use of fmt to keep it imported
	_ = fmt.Sprintf("grade=%d", g)
}
