/*
Package libbeatlite provides a light weight elasticsearch indexer.

Create an instance of a Client, and use its Send() method to send Messages.
*/
package libbeatlite

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var DEBUG = false

type Message struct {
	Source  map[string]interface{} // This is what gets indexed. Send() will add field "@timestamp", which will have current time in UTC
	Id      string                 // If set, the document will be indexed with this id (use it for idempotent indexing). If not set, random id will be assigned by elasticsearch
	Doctype string                 // If set, overrides the default set in Client
	Index   string                 // If set, overrides the default set in Client; this is the absolute value of the index (date will not be added)
	body    []byte
}

type Client struct {
	URL       string `json:"elasticsearch_url"`          // URL of the elasticsearch ingest node: http://locahost:9200
	Name      string `json:"beat_name"`                  // Index name is set by appending "-YYYY.MM.DD" to Name
	CA        string `json:"ca_cert_file_name"`          // Path of the file containing the PEM-encoded CA cert to use; if not set, host's default CAs are used
	Insecure  bool   `json:"ignore_invalid_server_cert"` // If True, skip TLS cert verification (expiration, host name, etc)
	Noop      bool   `json:"-"`                          // If True, do not call elasticsearch
	certPool  *x509.CertPool
	transport *http.Transport
	client    *http.Client
	hostname  string
}

func loadCert(path string) (*x509.CertPool, error) {

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading cert file: %v", err)
	}

	block, _ := pem.Decode(b)

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading ca cert: %v", err)
	}

	p := x509.NewCertPool()
	p.AddCert(c)

	return p, nil
}

func (c *Client) init() error {

	// if already initialized, do nothing
	if c.client != nil {
		return nil
	}

	if c.Name == "" {
		c.Name = "libbeatlite"
	}

	if c.CA != "" {
		p, err := loadCert(c.CA)
		if err != nil {
			return fmt.Errorf("error initializing client: %v", err)
		}
		c.certPool = p
	}

	t := &tls.Config{
		InsecureSkipVerify: c.Insecure,
		RootCAs:            c.certPool,
	}

	c.transport = &http.Transport{TLSClientConfig: t}
	c.client = &http.Client{Transport: c.transport}
	c.hostname, _ = os.Hostname()

	return nil
}

func (c *Client) prep(m *Message) error {

	f := "2006-01-02T15:04:05.000Z"

	// timestamp should be provided, but if not, use current time
	if m.Source["@timestamp"] == nil {
		m.Source["@timestamp"] = time.Now().UTC().Format(f)
	}

	// these fields are part of the libbeat "specification"
	m.Source["beat"] = map[string]string{
		"name":     c.Name,
		"hostname": c.hostname,
	}

	b, err := json.Marshal(m.Source)
	if err != nil {
		return fmt.Errorf("failed to marshal message source: %v", err)
	}
	m.body = b

	// if index wasn't explicitly set for the message, parse message timestamp
	// and set the index based on that. so if client beat code wants a
	// different indexing strategy, it can just provide the index for each
	// message; the overhead of date parsing is tiny according to benchmarks
	if m.Index == "" {
		s, ok := m.Source["@timestamp"].(string)
		if !ok {
			return fmt.Errorf("error parsing message timestamp: @timestamp field must be a string")
		}
		t, err := time.Parse(f, s)
		if err != nil {
			return fmt.Errorf("error parsing message timestamp, should be in format %q: %v", f, err)
		}
		m.Index = c.Name + "-" + t.UTC().Format("2006.01.02")
	}

	if m.Doctype == "" {
		m.Doctype = "log"
	}

	if DEBUG {
		log.Println(string(b))
	}
	return nil
}

// Synchronous send to Elasticsearch.
// If the Message doesn't have @timestamp field, it will be added, set to current time UTC. Returns server's response and error.
func (c *Client) Send(m *Message) ([]byte, error) {

	if err := c.init(); err != nil {
		return nil, err
	}

	// this needs to happen after client init, as default index and doctype for
	// the message are taken from the client
	if err := c.prep(m); err != nil {
		return nil, err
	}

	url := strings.Join([]string{c.URL, m.Index, m.Doctype, m.Id}, "/")
	if DEBUG {
		log.Println(url)
	}

	if c.Noop {
		if DEBUG {
			log.Println("NOOP: not sending request to elasticsearch")
		}
		return nil, nil
	}

	resp, err := c.client.Post(url, "application/json", bytes.NewBuffer(m.body))
	if err != nil {
		return nil, fmt.Errorf("error sending message: %v", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if DEBUG {
		log.Println(string(b))
	}
	return b, nil
}
