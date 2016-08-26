package libbeatlite

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	CERT = `-----BEGIN CERTIFICATE-----
MIIBhzCCAS6gAwIBAgIQHgITbVpRIKaNmR2fYlI+sjAKBggqhkjOPQQDAjAaMRgw
FgYDVQQKEw9wZWFrdW5pY29ybi5jb20wIBcNMTYwODA4MDAwMDAwWhgPMjEwMDAx
MDEwMDAwMDBaMBoxGDAWBgNVBAoTD3BlYWt1bmljb3JuLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJcyG7OUnJ1jdmAUl2ySInaEGgC8+tHKH4aSPVs94ILh
hEf8C9eRbsBMiZPenvffA+mXcfipWyrdBkXCBXhnPfmjVDBSMA4GA1UdDwEB/wQE
AwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBoGA1Ud
EQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjOPQQDAgNHADBEAiAcgFgftZEV
yDKZCbCilbu8q8mHE2eeS6ZzdNNmWwV/ywIgOraipxs0XwMYyL/RQm/Z4ONrYO17
3EwHAa3ckliFUkU=
-----END CERTIFICATE-----`
	KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKAntLrCeuxs3f6PbUz2uzgtSptpwpZOZpsLZrSTmLbMoAoGCCqGSM49
AwEHoUQDQgAElzIbs5ScnWN2YBSXbJIidoQaALz60cofhpI9Wz3gguGER/wL15Fu
wEyJk96e998D6Zdx+KlbKt0GRcIFeGc9+Q==
-----END EC PRIVATE KEY-----
`
)

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

func TestSend(t *testing.T) {

	ioutil.WriteFile("cert.pem", []byte(CERT), 0600)
	defer os.Remove("cert.pem")

	ioutil.WriteFile("key.pem", []byte(KEY), 0600)
	defer os.Remove("key.pem")

	hf := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%#v\n", r.URL)
		fmt.Fprintf(w, "%#v\n", r.Header)
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, "%s\n", b)
	}

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(hf))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()
	c := &Client{URL: s.URL, Insecure: false, CA: "cert.pem"}

	//	s := httptest.NewTLSServer(http.HandlerFunc(hf))
	//	defer s.Close()
	//	c := &Client{URL: s.URL, Insecure: true}

	m := &Message{Source: map[string]interface{}{"foo": "bar"}}

	r, err := c.Send(m)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s", r)

	// NOOP operation
	c = &Client{URL: "http://no-such-host:9200"}
	m = &Message{Source: map[string]interface{}{"foo": "bar"}}
	_, err = c.Send(m)
	if !strings.HasSuffix(err.Error(), "no such host") {
		t.Errorf("expected %q got %q", "no such host", err)
	}
	c.Noop = true
	_, err = c.Send(m)
	if err != nil {
		t.Error("unexpected error")
	}
}

func TestInit(t *testing.T) {

	c := &Client{CA: "nosuchfile.pem"}
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
