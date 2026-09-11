package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

var localClient = http.DefaultClient

func TestFetchIssuingCertificateSucceeds(t *testing.T) {
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))
	defer ts.Close()

	leafCert, _ := test.GetTestCert(t, []string{"invalid.URL", ts.URL}, testCA, caKey)

	cert, err := fetchIssuingCertificate(localClient, leafCert)
	if err != nil || cert == nil {
		t.Errorf("fetchIssuingCertificate() did not find valid intermediate cert: %v", err)
	}
}

func TestFetchIssuingCertificateReturnsErrorIfMalformedCertificateFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("these are some random bytes"))
	}))
	defer ts.Close()

	testCA, caKey := test.GetTestCert(t, nil, nil, nil)
	leafCert, _ := test.GetTestCert(t, []string{ts.URL}, testCA, caKey)

	_, err := fetchIssuingCertificate(localClient, leafCert)
	if err == nil {
		t.Fatal("expected fetchIssuingCertificate to fail with malformed cert")
	}
}

func TestGetAKIntermediateCertsSucceeds(t *testing.T) {
	// Create CA and corresponding server.
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	// Create intermediate cert and corresponding server.
	intermediateCert, intermediateKey := test.GetTestCert(t, []string{caServer.URL}, testCA, caKey)

	intermediateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(intermediateCert.Raw)
	}))
	defer intermediateServer.Close()

	// Create leaf cert.
	leafCert, _ := test.GetTestCert(t, []string{intermediateServer.URL}, intermediateCert, intermediateKey)

	certChain, err := GetAKIntermediateCerts(leafCert, localClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(certChain) != 2 {
		t.Fatalf("GetAKIntermediateCerts did not return the expected number of certificates: got %v, want 2", len(certChain))
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

type trackingTransport struct {
	body *trackingReadCloser
}

func (t *trackingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       t.body,
		Header:     make(http.Header),
	}, nil
}

func TestFetchIssuingCertificateClosesBodyOnNonOKStatus(t *testing.T) {
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)
	leafCert, _ := test.GetTestCert(t, []string{"http://example.com/cert"}, testCA, caKey)

	body := &trackingReadCloser{Reader: strings.NewReader("not found")}
	client := &http.Client{
		Transport: &trackingTransport{body: body},
	}

	_, err := fetchIssuingCertificate(client, leafCert)
	if err == nil {
		t.Fatal("expected error on non-OK status")
	}
	if !body.closed {
		t.Error("expected resp.Body to be closed when status code is not OK")
	}
}
