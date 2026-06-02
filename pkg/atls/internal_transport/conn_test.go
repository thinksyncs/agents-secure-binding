// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ultravioletrs/cocos/pkg/atls/ea"
	"github.com/ultravioletrs/cocos/pkg/atls/identitypolicy"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "internal-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestServerAllowsIdentityWithoutTLSConfig(t *testing.T) {
	cert := selfSignedCert(t)
	a, b := net.Pipe()

	serverTLS := tls.Server(a, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(b, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		conn, err := Server(serverTLS, &ServerConfig{
			Identity: cert,
		})
		serverCh <- result{conn: conn, err: err}
	}()

	go func() {
		conn, err := Client(clientTLS, &ClientConfig{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
		})
		clientCh <- result{conn: conn, err: err}
	}()

	srvRes := <-serverCh
	cliRes := <-clientCh

	if srvRes.err != nil {
		t.Fatalf("server failed: %v", srvRes.err)
	}
	if cliRes.err != nil {
		t.Fatalf("client failed: %v", cliRes.err)
	}

	defer srvRes.conn.Close()
	defer cliRes.conn.Close()
}

func TestValidateIdentityPolicySkipsDisabledPolicy(t *testing.T) {
	cfg := &ClientConfig{}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, nil); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyRequiresObservedIdentitySource(t *testing.T) {
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, nil)
	if !errors.Is(err, ErrMissingObservedIdentity) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, ErrMissingObservedIdentity)
	}
}

func TestValidateIdentityPolicyAcceptsObservedIdentity(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true, L3: true},
			Expected: identitypolicy.Values{Service: "payments", Agent: "agent-a"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "payments", Agent: "agent-a"},
				Binding: binding,
			}, nil
		},
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyAcceptsVerifiedGrantAndBinding(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = "identity-binding-nonce"
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true, L3: true},
			Expected: identitypolicy.Values{Service: "payments", Agent: "agent-a"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "payments", Agent: "agent-a"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyRejectsVerifiedGrantReplay(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = "identity-binding-nonce"
	replayCache := newTransportReplayCache()
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "payments"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
		IdentityReplay: replayCache,
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() first error = %v", err)
	}
	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("validateIdentityPolicy() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestValidateIdentityPolicyDoesNotConsumeReplayOnPolicyMismatch(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = "identity-binding-nonce"
	replayCache := newTransportReplayCache()
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "analytics"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
		IdentityReplay: replayCache,
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() mismatch error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
	cfg.IdentityGrant.Values.Service = "payments"
	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() second error = %v", err)
	}
}

func TestValidateIdentityPolicyRejectsObservedIdentityMismatch(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "analytics"},
				Binding: binding,
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestValidateIdentityPolicyRejectsUnboundAssertion(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values: identitypolicy.Values{Service: "payments"},
				Binding: identitypolicy.Binding{
					LeafPublicKeySHA256:  "wrong-leaf",
					RequestContextSHA256: "wrong-context",
					ExpiresAt:            time.Now().Add(time.Hour),
				},
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestValidateIdentityPolicyRejectsMissingRequestContext(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	validation.Context = nil
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L2B: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "payments"},
				Binding: bindingForAssertion(t, validationResultForIdentityPolicy(t)),
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if err == nil {
		t.Fatal("validateIdentityPolicy() error = nil, want missing context error")
	}
}

func validationResultForIdentityPolicy(t *testing.T) *ea.ValidationResult {
	t.Helper()

	cert := selfSignedCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return &ea.ValidationResult{
		Context: []byte("identity-policy-request-context"),
		Chain:   []*x509.Certificate{leaf},
	}
}

func bindingForAssertion(t *testing.T, validation *ea.ValidationResult) identitypolicy.Binding {
	t.Helper()

	binding, err := expectedIdentityBinding(validation)
	if err != nil {
		t.Fatal(err)
	}
	binding.ExpiresAt = time.Now().Add(time.Hour)
	return binding
}

type transportReplayCache struct {
	seen map[string]time.Time
}

func newTransportReplayCache() *transportReplayCache {
	return &transportReplayCache{seen: make(map[string]time.Time)}
}

func (c *transportReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}
