package main

import (
	"globalip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func now() rdl.Timestamp {
	return rdl.TimestampNow()
}

func defaultEndPoint() string {
	h := os.Getenv("HOST")
	if h != "" {
		p := os.Getenv("PORT")
		if p != "" {
			return h + ":" + p
		}
		return h + ":4080"
	}

	p := os.Getenv("PORT")
	if p != "" {
		return "0.0.0.0:" + p
	}

	endpoint := "0.0.0.0:4080"
	return endpoint
}

func defaultURL() string {
	url := "http://" + defaultEndPoint() + "/api/v1"
	return url
}

func main() {
	go checkGlobalIP()
	endpoint := defaultEndPoint()
	url := defaultURL()

	impl := new(GlobalIPImpl)
	impl.baseUrl = url

	handler := globalip.Init(impl, url, impl)

	if strings.HasPrefix(url, "https") {
		config, err := TLSConfiguration()
		if err != nil {
			log.Fatal("Cannot set up TLS: " + err.Error())
		}
		listener, err := tls.Listen("tcp", endpoint, config)
		if err != nil {
			panic(err)
		}
		log.Fatal(http.Serve(listener, handler))
	} else {
		log.Fatal(http.ListenAndServe(endpoint, handler))
	}
}

func checkGlobalIP() {
	ip := ""
	for true {
		client := globalip.NewClient("http://eu.httpbin.org", nil)
		out, err := client.GetGlobalIPResponse()
		if err != nil {
			log.Fatal("Cannot receive Global IP: " + err.Error())
		}
		if ip != string(out.Origin) {
			ip = string(out.Origin)
			log.Printf("Global IP: " + ip)
		}
		time.Sleep(300000 * time.Millisecond)
	}
}

//
// GlobalIPImpl is the implementation of the CapsHandler interface
//
type GlobalIPImpl struct {
	baseUrl  string
}

// GetContact implementation
func (impl *GlobalIPImpl) GetGlobalIPResponse(context *rdl.ResourceContext) (*globalip.GlobalIPResponse, error) {
	client := globalip.NewClient("http://httpbin.org", nil)
	response, err := client.GetGlobalIPResponse()
	if err != nil {
		errMsg := fmt.Sprintf("Unable to retrieve response details, Error: %v", err)
		return response, &rdl.ResourceError{Code: 200, Message: errMsg}
	}
	return response, nil
}

//
// the following is to support TLS-based authentication, and self-authorization that just logs what if *could* enforce.
//

func (impl *GlobalIPImpl) Authorize(action string, resource string, principal rdl.Principal) (bool, error) {
	fmt.Printf("[Authorize '%v' to %v on %v]\n", principal, action, resource)
	return true, nil
}

func (impl *GlobalIPImpl) Authenticate(context *rdl.ResourceContext) bool {
	certs := context.Request.TLS.PeerCertificates
	for _, cert := range certs {
		fmt.Printf("[Authenticated '%s' from TLS client cert]\n", cert.Subject.CommonName)
		context.Principal = &TLSPrincipal{cert}
		return true
	}
	return false
}

type TLSPrincipal struct {
	Cert *x509.Certificate
}

func (p *TLSPrincipal) String() string {
	return p.GetYRN()
}

func (p *TLSPrincipal) GetDomain() string {
	cn := p.Cert.Subject.CommonName
	i := strings.LastIndex(cn, ".")
	return cn[0:i]
}

func (p *TLSPrincipal) GetName() string {
	cn := p.Cert.Subject.CommonName
	i := strings.LastIndex(cn, ".")
	return cn[i+1:]
}

func (p *TLSPrincipal) GetYRN() string {
	return p.Cert.Subject.CommonName
}

func (p TLSPrincipal) GetCredentials() string {
	return ""
}

func (p TLSPrincipal) GetHTTPHeaderName() string {
	return ""
}

func TLSConfiguration() (*tls.Config, error) {
	capem, err := ioutil.ReadFile("certs/ca.cert")
	if err != nil {
		return nil, err
	}
	config := &tls.Config{}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		return nil, fmt.Errorf("Failed to append certs to pool")
	}
	config.RootCAs = certPool

	keypem, err := ioutil.ReadFile("keys/globalip.key")
	if err != nil {
		return nil, err
	}
	certpem, err := ioutil.ReadFile("certs/globalip.cert")
	if err != nil {
		return nil, err
	}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert

		config.ClientCAs = certPool

		//config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientAuth = tls.VerifyClientCertIfGiven
	}

	//Use only modern ciphers
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config, nil

}
