package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"path/filepath"

	"golang.org/x/crypto/ocsp"
	"gopkg.in/yaml.v3"
)

type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ALPN        string `json:"alpn"`
	ServerName  string `json:"server_name"`
}

type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotAfter  time.Time `json:"not_after"`
	NotBefore time.Time `json:"not_before"`
	KeyAlgo   string    `json:"key_algo"`
	KeyBits   int       `json:"key_bits"`
	IsCA      bool      `json:"is_ca"`
}

type Risk struct {
	Level  string `json:"level"`  // info|warn|crit
	Code   string `json:"code"`   // normalized risk code
	Detail string `json:"detail"` // human text
}

type OCSPInfo struct {
	Status     string     `json:"status"` // good|revoked|unknown|none
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	NextUpdate *time.Time `json:"next_update,omitempty"`
	ThisUpdate *time.Time `json:"this_update,omitempty"`
}

type HSTSInfo struct {
	Present           bool   `json:"present"`
	MaxAge            int64  `json:"max_age"`
	IncludeSubdomains bool   `json:"include_subdomains"`
	Preload           bool   `json:"preload"`
	Raw               string `json:"raw"`
}

type Result struct {
	Target string     `json:"target"`
	TLS    TLSInfo    `json:"tls"`
	Chain  []CertInfo `json:"chain"`
	OCSP   *OCSPInfo  `json:"ocsp,omitempty"`
	HSTS   *HSTSInfo  `json:"hsts,omitempty"`
	Risks  []Risk     `json:"risks"`
	Grade  int        `json:"grade"` // 1..5 (5 worst)
	Err    string     `json:"error,omitempty"`
}

type policy struct {
	Weights map[string]int `yaml:"weights"`
	Bands   []struct {
		Min   int `yaml:"min"`
		Max   int `yaml:"max"`
		Grade int `yaml:"grade"`
	} `yaml:"bands"`
}

var (
	timeout     = flag.Duration("timeout", 5*time.Second, "per-target timeout")
	jsonOut     = flag.Bool("json", false, "output JSON")
	port        = flag.Int("port", 443, "default port if none specified")
	caBundle    = flag.String("ca-bundle", "", "custom CA bundle (PEM)")
	concurrency = flag.Int("concurrency", 10, "parallel workers")
	doHSTS      = flag.Bool("hsts", false, "probe HSTS via HTTPS GET /")
	policyPath  = flag.String("policy", "", "path to policy.yaml for risk weights and grade bands")
	pol         policy
)

func init() {
	flag.Usage = func() {
		prog := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stdout, `
%s — TLS/SSL verification and tracing tool

Usage:
  %s [flags] host[:port] [host2[:port] ...]

Flags:
`, prog, prog)
		flag.PrintDefaults()

		fmt.Fprintf(os.Stdout, `
Examples:
  # Quick check with human-readable output
  %s example.com

  # JSON output plus HSTS probing for two hosts
  %s --json --hsts example.com www.cloudflare.com

  # Tight timeout, higher concurrency, and custom policy weights
  %s --timeout 3s --concurrency 20 --policy ./policy.yaml example.com

`, prog, prog, prog)
	}
}

func main() {
	flag.Parse()
	loadPolicy(*policyPath)

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	sem := make(chan struct{}, *concurrency)
	results := make([]Result, len(targets))

	for i, t := range targets {
		sem <- struct{}{}
		go func(i int, target string) {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			defer cancel()
			res := scanOne(ctx, target, *port, *caBundle, *doHSTS)
			res.Grade = gradeResult(res.Risks)
			results[i] = res
		}(i, t)
	}
	// drain to wait
	for j := 0; j < cap(sem); j++ {
		sem <- struct{}{}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	for _, r := range results {
		printHuman(r)
	}
}

func scanOne(ctx context.Context, target string, defaultPort int, caBundle string, doHSTS bool) Result {
	host, port := splitHostPortDefault(target, defaultPort)
	serverName := host

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return Result{Target: target, Err: err.Error()}
	}
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // manual verify to collect errors
	}
	if caBundle != "" {
		pool, perr := loadCABundle(caBundle)
		if perr != nil {
			return Result{Target: target, Err: perr.Error()}
		}
		cfg.RootCAs = pool
	}

	tlsConn := tls.Client(rawConn, cfg)
	defer tlsConn.Close()

	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- tlsConn.Handshake() }()

	select {
	case <-ctx.Done():
		return Result{Target: target, Err: "timeout during TLS handshake"}
	case herr := <-handshakeDone:
		if herr != nil {
			return Result{Target: target, Err: "handshake failed: " + herr.Error()}
		}
	}

	cs := tlsConn.ConnectionState()
	res := Result{Target: target}
	res.TLS = TLSInfo{
		Version:     tlsVersionString(cs.Version),
		CipherSuite: cipherSuiteString(cs.CipherSuite),
		ALPN:        cs.NegotiatedProtocol,
		ServerName:  serverName,
	}

	for _, cert := range cs.PeerCertificates {
		res.Chain = append(res.Chain, certInfo(cert))
	}

	// Chain verification
	if err := verifyChain(cs, serverName, cfg.RootCAs); err != nil {
		res.Risks = append(res.Risks, Risk{Level: "crit", Code: "CHAIN_VERIFY_FAILED", Detail: err.Error()})
	}

	// Expiry and TLS risks
	res.Risks = append(res.Risks, expiryRisks(cs.PeerCertificates)...)
	res.Risks = append(res.Risks, protocolRisks(cs.Version)...)
	res.Risks = append(res.Risks, cipherRisks(cs.CipherSuite, cs.Version)...)

	// OCSP stapling
	if len(cs.OCSPResponse) > 0 && len(cs.PeerCertificates) > 0 {
		oc := parseOCSP(cs)
		res.OCSP = oc
		switch strings.ToLower(oc.Status) {
		case "revoked":
			res.Risks = append(res.Risks, Risk{Level: "crit", Code: "OCSP_REVOKED", Detail: "OCSP stapled status: revoked"})
		case "unknown":
			res.Risks = append(res.Risks, Risk{Level: "warn", Code: "OCSP_UNKNOWN", Detail: "OCSP stapled status: unknown"})
		}
		if oc.NextUpdate != nil && time.Now().After(*oc.NextUpdate) {
			res.Risks = append(res.Risks, Risk{Level: "warn", Code: "OCSP_STAPLE_STALE", Detail: "stapled OCSP nextUpdate is in the past"})
		}
	} else {
		// No stapling is common; not a risk by default policy
		res.OCSP = &OCSPInfo{Status: "none"}
	}

	// HSTS probe (optional)
	if doHSTS {
		if hi, risks := probeHSTS(ctx, host, cfg); hi != nil {
			res.HSTS = hi
			res.Risks = append(res.Risks, risks...)
		}
	}

	return res
}

func splitHostPortDefault(target string, defaultPort int) (string, string) {
	if strings.Contains(target, ":") {
		host, port, err := net.SplitHostPort(target)
		if err == nil {
			return host, port
		}
	}
	return target, fmt.Sprintf("%d", defaultPort)
}

func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("failed to parse any certs in CA bundle")
	}
	return pool, nil
}

func verifyChain(cs tls.ConnectionState, dnsName string, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no peer certificates")
	}
	inter := x509.NewCertPool()
	for i, c := range cs.PeerCertificates {
		if i == 0 {
			continue // leaf
		}
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: inter,
	}
	if roots != nil {
		opts.Roots = roots
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}

func certInfo(c *x509.Certificate) CertInfo {
	bits := 0
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits = k.Size() * 8
	default:
		// ECDSA, Ed25519: showing 0 is fine for MVP
	}
	return CertInfo{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		NotAfter:  c.NotAfter,
		NotBefore: c.NotBefore,
		KeyAlgo:   c.PublicKeyAlgorithm.String(),
		KeyBits:   bits,
		IsCA:      c.IsCA,
	}
}

func expiryRisks(chain []*x509.Certificate) []Risk {
	var out []Risk
	if len(chain) == 0 {
		out = append(out, Risk{Level: "crit", Code: "NO_CERTS", Detail: "no certificates presented"})
		return out
	}
	leaf := chain[0]
	ttl := time.Until(leaf.NotAfter)
	switch {
	case ttl <= 7*24*time.Hour:
		out = append(out, Risk{Level: "crit", Code: "EXPIRY_SOON_CRIT", Detail: fmt.Sprintf("leaf expires in %s", ttl.Truncate(time.Hour))})
	case ttl <= 30*24*time.Hour:
		out = append(out, Risk{Level: "warn", Code: "EXPIRY_SOON_WARN", Detail: fmt.Sprintf("leaf expires in %s", ttl.Truncate(time.Hour))})
	}
	return out
}

func protocolRisks(ver uint16) []Risk {
	switch ver {
	case tls.VersionTLS10, tls.VersionTLS11:
		return []Risk{{Level: "crit", Code: "TLS_VERSION_OLD", Detail: tlsVersionString(ver)}}
	case tls.VersionTLS12, tls.VersionTLS13:
		return nil
	default:
		return []Risk{{Level: "warn", Code: "TLS_VERSION_OLD", Detail: fmt.Sprintf("unknown 0x%x", ver)}}
	}
}

func cipherRisks(csID uint16, ver uint16) []Risk {
	name := cipherSuiteString(csID)
	weakTokens := []string{"RC4", "3DES", " DES_", "MD5", "NULL", "EXPORT"}
	for _, t := range weakTokens {
		if strings.Contains(name, t) {
			return []Risk{{Level: "crit", Code: "WEAK_CIPHER", Detail: name}}
		}
	}
	if ver == tls.VersionTLS12 && strings.Contains(name, "_CBC_") {
		return []Risk{{Level: "warn", Code: "CBC_ON_TLS12", Detail: name}}
	}
	return nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func cipherSuiteString(id uint16) string {
	cs := tls.CipherSuiteName(id)
	if cs == "" {
		return fmt.Sprintf("0x%x", id)
	}
	return cs
}

// OCSP parsing from stapled response
func parseOCSP(cs tls.ConnectionState) *OCSPInfo {
	info := &OCSPInfo{Status: "unknown"}
	leaf := cs.PeerCertificates[0]
	var issuer *x509.Certificate
	if len(cs.PeerCertificates) > 1 {
		issuer = cs.PeerCertificates[1]
	}
	resp, err := ocsp.ParseResponse(cs.OCSPResponse, issuer)
	if err != nil {
		info.Status = "unknown"
		return info
	}
	switch resp.Status {
	case ocsp.Good:
		info.Status = "good"
	case ocsp.Revoked:
		info.Status = "revoked"
		if !resp.RevokedAt.IsZero() {
			tt := resp.RevokedAt
			info.RevokedAt = &tt
		}
	default:
		info.Status = "unknown"
	}
	if !resp.NextUpdate.IsZero() {
		nu := resp.NextUpdate
		info.NextUpdate = &nu
	}
	if !resp.ThisUpdate.IsZero() {
		tu := resp.ThisUpdate
		info.ThisUpdate = &tu
	}
	// sanity: ensure the response matches the leaf we think it does (optional)
	_ = leaf
	return info
}

// HSTS probing
func probeHSTS(ctx context.Context, host string, tlsCfg *tls.Config) (*HSTSInfo, []Risk) {
	u := "https://" + host + "/"
	tr := &http.Transport{
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     2 * time.Second,
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		DialContext: (&net.Dialer{
			Timeout:  *timeout / 2,
			Deadline: time.Now().Add(*timeout / 2),
		}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   *timeout / 2,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// follow up to 3 redirects max to land on final HSTS-bearing host
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err != nil {
		// Treat as no HSTS info; don't spam hard errors
		return &HSTSInfo{Present: false}, []Risk{{Level: "info", Code: "HSTS_MISSING", Detail: "unable to fetch HSTS: " + err.Error()}}
	}
	defer resp.Body.Close()

	h := resp.Header.Get("Strict-Transport-Security")
	hi := &HSTSInfo{Raw: h}
	var risks []Risk
	if h == "" {
		hi.Present = false
		risks = append(risks, Risk{Level: "warn", Code: "HSTS_MISSING", Detail: "Strict-Transport-Security header not present"})
		return hi, risks
	}
	hi.Present = true
	hi.MaxAge = parseHSTSMaxAge(h)
	hi.IncludeSubdomains = strings.Contains(strings.ToLower(h), "includesubdomains")
	hi.Preload = strings.Contains(strings.ToLower(h), "preload")

	if hi.MaxAge < 15552000 { // < 180 days
		risks = append(risks, Risk{Level: "info", Code: "HSTS_SHORT_MAXAGE", Detail: fmt.Sprintf("max-age=%d < 15552000", hi.MaxAge)})
	}
	if !hi.IncludeSubdomains {
		risks = append(risks, Risk{Level: "info", Code: "HSTS_NO_SUBDOMAINS", Detail: "includeSubDomains not set"})
	}
	return hi, risks
}

var maxAgeRe = regexp.MustCompile(`(?i)max-age\s*=\s*([0-9]+)`)

func parseHSTSMaxAge(h string) int64 {
	m := maxAgeRe.FindStringSubmatch(h)
	if len(m) != 2 {
		return 0
	}
	v, _ := strconv.ParseInt(m[1], 10, 64)
	return v
}

// ---------- Grading ----------

func loadPolicy(path string) {
	// default
	pol = policy{}
	if err := yaml.Unmarshal([]byte(defaultPolicyYAML), &pol); err != nil {
		// panic is fine here; default YAML is valid
		panic(err)
	}
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// keep default policy; print to stderr for visibility
		fmt.Fprintf(os.Stderr, "warning: could not read policy file: %v (using defaults)\n", err)
		return
	}
	var custom policy
	if err := yaml.Unmarshal(b, &custom); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse policy file: %v (using defaults)\n", err)
		return
	}
	// shallow merge: custom overrides defaults
	if custom.Weights != nil {
		for k, v := range custom.Weights {
			pol.Weights[k] = v
		}
	}
	if len(custom.Bands) > 0 {
		pol.Bands = custom.Bands
	}
}

func gradeResult(risks []Risk) int {
	score := 0
	for _, r := range risks {
		if w, ok := pol.Weights[r.Code]; ok {
			score += w
		}
	}
	// pick band
	for _, b := range pol.Bands {
		if score >= b.Min && score <= b.Max {
			return b.Grade
		}
	}
	// if no band matched, worst case
	return 5
}

const defaultPolicyYAML = `
weights:
  CHAIN_VERIFY_FAILED: 50
  NO_CERTS: 50
  EXPIRY_SOON_WARN: 10
  EXPIRY_SOON_CRIT: 40
  TLS_VERSION_OLD: 40
  CBC_ON_TLS12: 10
  WEAK_CIPHER: 40
  OCSP_REVOKED: 80
  OCSP_UNKNOWN: 10
  OCSP_STAPLE_STALE: 15
  HSTS_MISSING: 8
  HSTS_SHORT_MAXAGE: 6
  HSTS_NO_SUBDOMAINS: 2
bands:
  - { min: 0,   max: 5,   grade: 1 }
  - { min: 6,   max: 20,  grade: 2 }
  - { min: 21,  max: 45,  grade: 3 }
  - { min: 46,  max: 80,  grade: 4 }
  - { min: 81,  max: 1000, grade: 5 }
`

// ---------- Human output ----------

func printHuman(r Result) {
	fmt.Printf("=== %s ===\n", r.Target)
	if r.Err != "" {
		fmt.Printf("ERROR: %s\n\n", r.Err)
		return
	}
	fmt.Printf("TLS: %-6s  Cipher: %s  ALPN: %s  SNI: %s  Grade: %d/5\n",
		r.TLS.Version, r.TLS.CipherSuite, emptyDash(r.TLS.ALPN), r.TLS.ServerName, r.Grade)
	if len(r.Chain) > 0 {
		leaf := r.Chain[0]
		ttl := time.Until(leaf.NotAfter).Truncate(time.Hour)
		fmt.Printf("Leaf: %s  →  %s  Expires: %s  (in %s)\n", leaf.Subject, leaf.Issuer, leaf.NotAfter.Format(time.RFC3339), ttl)
	}
	if r.OCSP != nil {
		fmt.Printf("OCSP: %s", r.OCSP.Status)
		if r.OCSP.NextUpdate != nil {
			fmt.Printf("  nextUpdate=%s", r.OCSP.NextUpdate.UTC().Format(time.RFC3339))
		}
		fmt.Println()
	}
	if r.HSTS != nil {
		if r.HSTS.Present {
			fmt.Printf("HSTS: present max-age=%d includeSubDomains=%v preload=%v\n", r.HSTS.MaxAge, r.HSTS.IncludeSubdomains, r.HSTS.Preload)
		} else {
			fmt.Printf("HSTS: missing\n")
		}
	}
	if len(r.Risks) == 0 {
		fmt.Println("Risks: none")
	} else {
		fmt.Println("Risks:")
		for _, k := range r.Risks {
			fmt.Printf("  - [%s] %s: %s\n", strings.ToUpper(k.Level), k.Code, k.Detail)
		}
	}
	fmt.Println()
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
