package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCallerRecordsUnixCaller(t *testing.T) {
	var got Caller
	var ok bool
	h := WithCaller(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = CallerFrom(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/profiles", nil))

	if !ok {
		t.Fatal("no caller on the context")
	}
	if got.Transport != TransportUnix {
		t.Errorf("Transport = %q, want %q", got.Transport, TransportUnix)
	}
	// SO_PEERCRED is unimplemented, so a local caller has no name yet. This
	// asserts the current honest answer rather than a placeholder.
	if got.Name != "" {
		t.Errorf("Name = %q, want empty for a unix caller", got.Name)
	}
}

func TestWithCallerRecordsCertificateCommonName(t *testing.T) {
	var got Caller
	h := WithCaller(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = CallerFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/profiles", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "sandbox-caller"}},
	}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.Transport != TransportTLS {
		t.Errorf("Transport = %q, want %q", got.Transport, TransportTLS)
	}
	if got.Name != "sandbox-caller" {
		t.Errorf("Name = %q, want sandbox-caller", got.Name)
	}
}

func TestCallerFromReportsAbsence(t *testing.T) {
	if _, ok := CallerFrom(context.Background()); ok {
		t.Fatal("CallerFrom reported a caller on a bare context")
	}
}
