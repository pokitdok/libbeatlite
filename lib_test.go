package libbeatlite

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	CACert = `-----BEGIN CERTIFICATE-----
MIIBoDCCAUegAwIBAgIJALJkPlMlD2SyMAoGCCqGSM49BAMCMC0xETAPBgNVBAoM
CFBva2l0ZG9rMRgwFgYDVQQLDA9FbGFzdGljc2VhcmNoQ0EwHhcNMTYwOTEyMjE0
NjUxWhcNMjYwOTEwMjE0NjUxWjAtMREwDwYDVQQKDAhQb2tpdGRvazEYMBYGA1UE
CwwPRWxhc3RpY3NlYXJjaENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw63/
upWqvJULCNTlH+SpD44bQLiGwChAehi+as6NeUdSY0vCuTH/MqTgvt0jgocsUSfD
cIsRa3gUREQLi9kaKKNQME4wHQYDVR0OBBYEFJ7tlS3c3RlGjEuaN68F9SrZCBQl
MB8GA1UdIwQYMBaAFJ7tlS3c3RlGjEuaN68F9SrZCBQlMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwIDRwAwRAIgG1IQRbIJmYMyQ81jE4k8zP/iGGfPdrxouJ2Fkffl
WlECIFPjFjdKZLP9JmEZeLfirPN1mxvDR9mxfnWjYH20GZ87
-----END CERTIFICATE-----`
	ServerCert = `-----BEGIN CERTIFICATE-----
MIIB/TCCAaOgAwIBAgIJAMgrOTUguPIOMAoGCCqGSM49BAMCMC0xETAPBgNVBAoM
CFBva2l0ZG9rMRgwFgYDVQQLDA9FbGFzdGljc2VhcmNoQ0EwHhcNMTYwOTEyMjE0
NjUxWhcNMTYxMDEyMjE0NjUxWjA8MREwDwYDVQQKDAhQb2tpdGRvazEWMBQGA1UE
CwwNRWxhc3RpY3NlYXJjaDEPMA0GA1UEAwwGc2VydmVyMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAElGU2OW0KREjecFDB5ZbKQJwziQoaKd44ZLBwKrK7qRvFum9x
wXk9sFhQ+iDKrDQ34pXWMpohHdPZ4U9zHco3PKOBnDCBmTAfBgNVHSMEGDAWgBSe
7ZUt3N0ZRoxLmjevBfUq2QgUJTAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF4DAg
BgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGgYDVR0RBBMwEYIJbG9j
YWxob3N0hwR/AAABMB0GA1UdDgQWBBRWlMuZmRBaaX1CKodkPZCg9kJR/TAKBggq
hkjOPQQDAgNIADBFAiBHtd0w9A+D+NAsgWg9RxtLeML37vBP9xMODGyw/lkpnAIh
AJlFOWO4MltuQ7nkx6dCSyzN7CB2idpqkGu7kdU3GxEj
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBoDCCAUegAwIBAgIJALJkPlMlD2SyMAoGCCqGSM49BAMCMC0xETAPBgNVBAoM
CFBva2l0ZG9rMRgwFgYDVQQLDA9FbGFzdGljc2VhcmNoQ0EwHhcNMTYwOTEyMjE0
NjUxWhcNMjYwOTEwMjE0NjUxWjAtMREwDwYDVQQKDAhQb2tpdGRvazEYMBYGA1UE
CwwPRWxhc3RpY3NlYXJjaENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw63/
upWqvJULCNTlH+SpD44bQLiGwChAehi+as6NeUdSY0vCuTH/MqTgvt0jgocsUSfD
cIsRa3gUREQLi9kaKKNQME4wHQYDVR0OBBYEFJ7tlS3c3RlGjEuaN68F9SrZCBQl
MB8GA1UdIwQYMBaAFJ7tlS3c3RlGjEuaN68F9SrZCBQlMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwIDRwAwRAIgG1IQRbIJmYMyQ81jE4k8zP/iGGfPdrxouJ2Fkffl
WlECIFPjFjdKZLP9JmEZeLfirPN1mxvDR9mxfnWjYH20GZ87
-----END CERTIFICATE-----`
	ServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEID+tMOJiT3yv0oJDjZT8taV3IYySOloQCkUtY80EogCDoAoGCCqGSM49
AwEHoUQDQgAElGU2OW0KREjecFDB5ZbKQJwziQoaKd44ZLBwKrK7qRvFum9xwXk9
sFhQ+iDKrDQ34pXWMpohHdPZ4U9zHco3PA==
-----END EC PRIVATE KEY-----`
	ClientCert = `-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIJAMgrOTUguPINMAoGCCqGSM49BAMCMC0xETAPBgNVBAoM
CFBva2l0ZG9rMRgwFgYDVQQLDA9FbGFzdGljc2VhcmNoQ0EwHhcNMTYwOTEyMjE0
NjUxWhcNMTYxMDEyMjE0NjUxWjA8MREwDwYDVQQKDAhQb2tpdGRvazEWMBQGA1UE
CwwNRWxhc3RpY3NlYXJjaDEPMA0GA1UEAwwGY2xpZW50MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEKYaRm6adybrQI5D4VTXzSFwHfSfRW7o4cjonjzusSGXQwIDP
H2qkKnfFRfo9zIM8c/IsIo3iSFJSbc1PvlughaM1MDMwDAYDVR0TAQH/BAIwADAL
BgNVHQ8EBAMCBeAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwID
RwAwRAIgOydD7Q0ANud1yRaGyAxYQx+77Biw6wbhhtkGz5+k54kCIAK6ZwZ6V4fV
ZZ/3RpgIRLwmIuWQFZrd5nuHvBW/RfwB
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBoDCCAUegAwIBAgIJALJkPlMlD2SyMAoGCCqGSM49BAMCMC0xETAPBgNVBAoM
CFBva2l0ZG9rMRgwFgYDVQQLDA9FbGFzdGljc2VhcmNoQ0EwHhcNMTYwOTEyMjE0
NjUxWhcNMjYwOTEwMjE0NjUxWjAtMREwDwYDVQQKDAhQb2tpdGRvazEYMBYGA1UE
CwwPRWxhc3RpY3NlYXJjaENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw63/
upWqvJULCNTlH+SpD44bQLiGwChAehi+as6NeUdSY0vCuTH/MqTgvt0jgocsUSfD
cIsRa3gUREQLi9kaKKNQME4wHQYDVR0OBBYEFJ7tlS3c3RlGjEuaN68F9SrZCBQl
MB8GA1UdIwQYMBaAFJ7tlS3c3RlGjEuaN68F9SrZCBQlMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwIDRwAwRAIgG1IQRbIJmYMyQ81jE4k8zP/iGGfPdrxouJ2Fkffl
WlECIFPjFjdKZLP9JmEZeLfirPN1mxvDR9mxfnWjYH20GZ87
-----END CERTIFICATE-----`
	ClientKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM59Y5TnjqxXI1+wqczuQ04tfa+k2NNNii5wZ4XofsDdoAoGCCqGSM49
AwEHoUQDQgAEKYaRm6adybrQI5D4VTXzSFwHfSfRW7o4cjonjzusSGXQwIDPH2qk
KnfFRfo9zIM8c/IsIo3iSFJSbc1PvlughQ==
-----END EC PRIVATE KEY-----`
)

func TestSend(t *testing.T) {

	r201 := func(w http.ResponseWriter, r *http.Request) {
		ioutil.ReadAll(r.Body)
		w.WriteHeader(201)
	}

	r400 := func(w http.ResponseWriter, r *http.Request) {
		ioutil.ReadAll(r.Body)
		http.Error(w, "not authorized", 401)
	}

	serverCert, err := tls.X509KeyPair([]byte(ServerCert), []byte(ServerKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(CACert))

	tmpCACertFile, _ := ioutil.TempFile("", "libbeatlite-")
	tmpCACertFile.Write([]byte(CACert))
	defer os.Remove(tmpCACertFile.Name())

	tmpClientCertFile, _ := ioutil.TempFile("", "libbeatlite-")
	tmpClientCertFile.Write([]byte(ClientCert))
	defer os.Remove(tmpClientCertFile.Name())

	tmpClientKeyFile, _ := ioutil.TempFile("", "libbeatlite-")
	tmpClientKeyFile.Write([]byte(ClientKey))
	defer os.Remove(tmpClientKeyFile.Name())

	tests := []struct {
		name        string
		handlerFunc http.HandlerFunc
		shouldPass  bool
		tls         tls.Config
		client      Client
	}{
		{
			"tls no ca cert expect error", r201, false,
			tls.Config{Certificates: []tls.Certificate{serverCert}},
			Client{},
		},
		{
			"tls insecure response 201", r201, true,
			tls.Config{Certificates: []tls.Certificate{serverCert}},
			Client{Insecure: true},
		},
		{
			"tls insecure response 400 expect error", r400, false,
			tls.Config{Certificates: []tls.Certificate{serverCert}},
			Client{Insecure: true},
		},
		{
			"tls client cert not required and not provided", r201, true,
			tls.Config{Certificates: []tls.Certificate{serverCert}},
			Client{Insecure: false, CACertFile: tmpCACertFile.Name()},
		},
		{
			"tls client cert not required but provided", r201, true,
			tls.Config{Certificates: []tls.Certificate{serverCert}},
			Client{Insecure: false, CACertFile: tmpCACertFile.Name(), ClientCertFile: tmpClientCertFile.Name(), ClientKeyFile: tmpClientKeyFile.Name()},
		},
		{
			"tls client cert required but not provided expect error", r201, false,
			tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool},
			Client{Insecure: false, CACertFile: tmpCACertFile.Name()},
		},
		{
			"tls client cert required but key not provided expect error", r201, false,
			tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool},
			Client{Insecure: false, CACertFile: tmpCACertFile.Name(), ClientCertFile: tmpClientCertFile.Name()},
		},
		{
			"tls client cert required and provided", r201, true,
			tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool},
			Client{Insecure: false, CACertFile: tmpCACertFile.Name(), ClientCertFile: tmpClientCertFile.Name(), ClientKeyFile: tmpClientKeyFile.Name()},
		},
	}

	m := &Message{Source: map[string]interface{}{"foo": "bar"}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(test.handlerFunc))
			s.TLS = &test.tls
			s.StartTLS()
			defer s.Close()
			c := &test.client
			c.URL = s.URL
			r, err := c.Send(m)
			if err != nil {
				log.Println(err)
				if test.shouldPass {
					t.Errorf("unexpected error: %v", err)
				}
			}
			fmt.Printf("%s", r)
		})
	}

}

func TestNoop(t *testing.T) {

	c := &Client{URL: "http://no-such-host:9200"}
	m := &Message{Source: map[string]interface{}{"foo": "bar"}}
	_, err := c.Send(m)
	if !strings.HasSuffix(err.Error(), "no such host") {
		t.Errorf("expected %q got %q", "no such host", err)
	}

	c.Noop = true
	_, err = c.Send(m)
	if err != nil {
		t.Error("unexpected error")
	}

}

func TestPrep(t *testing.T) {

	today := time.Now().UTC().Format("2006.01.02")

	c := &Client{Name: "libbeatlite"}
	m := &Message{Source: map[string]interface{}{"foo": "bar"}}

	err := c.prep(m)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if m.Doctype != "log" {
		t.Errorf("expected doctype %q got %q", "log", m.Doctype)
	}

	i := c.Name + "-" + today
	if m.Index != i {
		t.Errorf("expected index %q got %q", i, m.Index)
	}

	if _, ok := m.Source["@timestamp"].(string); !ok {
		t.Error("expected @timestamp to be a string")
	}

	m = &Message{Source: map[string]interface{}{"foo": "bar"}, Index: "foo"}
	c.prep(m)
	if m.Index != "foo" {
		t.Errorf("expected index %q got %q", "foo", m.Index)
	}

	m = &Message{Source: map[string]interface{}{"foo": "bar", "@timestamp": "2016-07-29T21:04:26.424Z"}}
	c.prep(m)
	if m.Index != "libbeatlite-2016.07.29" {
		t.Errorf("expected index %q got %q", "libbeatlite-2016.07.29", m.Index)
	}

}

func BenchmarkPrep(b *testing.B) {

	c := &Client{}
	m := &Message{Source: map[string]interface{}{"foo": "bar"}}

	for i := 0; i < b.N; i++ {
		c.prep(m)
	}

}

func TestInit(t *testing.T) {

	c := &Client{CACertFile: "nosuchfile.pem"}
	err := c.init()
	if err == nil {
		t.Error("expected error")
	}

}

func ExampleClient() {

	c := &Client{
		URL:  "http://no-such-host:9200",
		Name: "testbeatlite",
	}
	m := &Message{Source: map[string]interface{}{"foo": "bar"}}
	c.Send(m)

}
