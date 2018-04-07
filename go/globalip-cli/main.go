package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	rdl "globalip"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func defaultURL() string {
	s := os.Getenv("URL")
	if s != "" {
		return s
	}
	return "http://httpbin.org"
}

func defaultUser() string {
	return os.Getenv("USER")
}

func defaultSocksProxy() string {
	return os.Getenv("SOCKS5_PROXY")
}

// isFreshFile checks the file's last modification time
// and returns true the file was updated within maxAge
// (file is "fresh"), false otherwise (file is "stale").
func isFreshFile(filename string, maxAge float64) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	delta := time.Since(info.ModTime())
	// return false if delta exceeds maxAge
	tooOld := delta.Minutes() > maxAge
	return !tooOld
}

func getCachedToken() string {
	tokenFile := os.Getenv("HOME") + "/.token"
	if isFreshFile(tokenFile, 45) {
		data, err := ioutil.ReadFile(tokenFile)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
		fmt.Printf("Couldn't read the file, error: %v\n", err)
	}
	return ""
}

func usage() string {
	var buf bytes.Buffer
	buf.WriteString("usage: globalip-cli\n")
	buf.WriteString(" flags:\n")
	buf.WriteString("   -c cacert_file               CA Certificate file path\n")
	buf.WriteString("   -k                           Disable peer verification of SSL certificates.\n")
	buf.WriteString("   -client-cert-file cert_file  Client Certificate file path\n")
	buf.WriteString("   -client-key-file key_file    Client Private Key file path\n")
	buf.WriteString("   -s host:port                 The SOCKS5 proxy to route requests through\n")
	buf.WriteString("   -u url                       Base URL of the global ip api to use\n")
	buf.WriteString("                                (default URL=" + defaultURL() + ")\n")
	buf.WriteString("\n")
	return buf.String()
}

func main() {
	pCACert := flag.String("c", "", "CA Certificate file path")
	pSkipVerify := flag.Bool("k", false, "Disable peer verification of SSL certificates")
	pKey := flag.String("client-key-file", "", "the client private key file")
	pCert := flag.String("client-cert-file", "", "the client certificate file")
	pSocks := flag.String("s", defaultSocksProxy(), "The SOCKS5 proxy to route requests through, i.e. 127.0.0.1:1080")
	pURL := flag.String("u", defaultURL(), "Base URL of the global ip api to use")
	flag.Usage = func() {
		fmt.Println(usage())
	}

	// first we need to parse our arguments based
	// on the flags we defined above

	flag.Parse()

	URL := *pURL

	if URL == "" {
		log.Fatalf("No Url specified")
	}

	// now process our request

	args := flag.Args()
	if len(args) == 1 {
		if args[0] == "help" {
			fmt.Println(usage())
			return
		} else if args[0] == "version" {
			if VERSION == "" {
				fmt.Println("globalip (development version)")
			} else {
				fmt.Println("globalip " + VERSION + " " + BUILD_DATE)
			}
			return
		}
	}

	if *pSocks == "" {
		pSocks = nil
	}
	if *pCACert == "" {
		pCACert = nil
	}
	if *pKey == "" && *pCert == "" {
		pKey = nil
		pCert = nil
	} else if *pKey == "" || *pCert == "" {
		log.Fatalf("Both service key and certificate must be provided")
	}
	tr := getHttpTransport(pSocks, pKey, pCert, pCACert, *pSkipVerify)
	var err error
	client := rdl.NewClient(URL, tr)

	out, err := client.GetResponse()
	if err != nil {
		log.Fatalf("Unable to retrieve response details, err: %v", err)
	}
	fmt.Println(out.Origin)
	os.Exit(0)
}

func getHttpTransport(socksProxy, keyFile, certFile, caCertFile *string, skipVerify bool) *http.Transport {
	tr := http.Transport{}
	if socksProxy != nil {
		dialer := &net.Dialer{}
		dialSocksProxy, err := proxy.SOCKS5("tcp", *socksProxy, nil, dialer)
		if err == nil {
			tr.Dial = dialSocksProxy.Dial
		}
	}
	if keyFile != nil || caCertFile != nil || skipVerify {
		config, err := GetTLSConfigFromFiles(certFile, keyFile, caCertFile)
		if err != nil {
			log.Fatalf("Unable to generate TLS config object, error: %v", err)
		}
		if skipVerify {
			config.InsecureSkipVerify = skipVerify
		}
		tr.TLSClientConfig = config
	}
	return &tr
}

func GetTLSConfigFromFiles(certFile, keyFile, caCertFile *string) (*tls.Config, error) {
	var keyPem []byte
	var certPem []byte
	var caCertPem []byte
	var err error
	if keyFile != nil {
		keyPem, err = ioutil.ReadFile(*keyFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read keyfile: %q, error: %v", *keyFile, err)
		}

		certPem, err = ioutil.ReadFile(*certFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read certfile: %q, error: %v", *certFile, err)
		}
	}
	if caCertFile != nil {
		caCertPem, err = ioutil.ReadFile(*caCertFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read ca certfile: %q, error: %v", *caCertFile, err)
		}
	}
	return GetTLSConfig(certPem, keyPem, caCertPem)
}

func GetTLSConfig(certPem, keyPem, caCertPem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if keyPem != nil {
		clientCert, err := tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			return nil, fmt.Errorf("Unable to formulate clientCert from key and cert bytes, error: %v", err)
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = clientCert
	}
	if caCertPem != nil {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCertPem) {
			return nil, fmt.Errorf("Unable to append CA Certificate to pool")
		}
		config.RootCAs = certPool
	}
	return config, nil
}

func normalizeServerURL(url, suffix string) string {
	normURL := ""
	if strings.HasSuffix(url, suffix) {
		normURL = url[:len(url)-len(suffix)] + "/"
	} else if last := len(url) - 1; last >= 0 && url[last] == '/' {
		normURL = url
	} else {
		normURL = url + "/"
	}
	return normURL
}
