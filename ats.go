// ATS checker verify if the given path provides acceptable cipher for ATS.
//
// App Transport Security Technote: App Transport Security Technote
// https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/
//
// Usage: ats_checker https://path/to/url
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
)

// acceptable ciphers from https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/
var acceptableCipher = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
}

var acceptableSignatureAlgorithm = []x509.SignatureAlgorithm{
	// x509.MD2WithRSA,
	// x509.MD5WithRSA,
	// x509.SHA1WithRSA,
	x509.SHA256WithRSA,
	x509.SHA384WithRSA,
	x509.SHA512WithRSA,
	// x509.DSAWithSHA1,
	// x509.DSAWithSHA256,
	// x509.ECDSAWithSHA1,
	x509.ECDSAWithSHA256,
	x509.ECDSAWithSHA384,
	x509.ECDSAWithSHA512,
}

// check verify ciphers and TLS version
func check(resp *http.Response) (bool, error) {
	var cipherCheck = false
	var signatureAlgorithmCheck = false

	if resp.TLS == nil {
		return false, nil
	}
	if resp.TLS.Version != tls.VersionTLS12 {
		return false, nil
	}

	for _, c := range acceptableCipher {
		if resp.TLS.CipherSuite == c {
			cipherCheck = true
			break
		}
	}

	for _, s := range acceptableSignatureAlgorithm {
		if resp.TLS.PeerCertificates[0].SignatureAlgorithm == s {
			signatureAlgorithmCheck = true
			break
		}
	}

	return cipherCheck && signatureAlgorithmCheck, nil
}

func main() {
	insecure := flag.Bool("insecure", false, "allow to connect to SSL sites without certs")
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Println("Usage: ats_checker https://path/to/url")
		os.Exit(0)
	}
	url := flag.Arg(0)
	if *insecure {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	if r, err := check(resp); err != nil {
		panic(err)
	} else if r == false {
		fmt.Printf("%s is not acceptable for ATS\n debug info: %#v\n", url, resp.TLS)
		os.Exit(1)
	}

	fmt.Printf("%s is acceptable for ATS\n", url)
	os.Exit(0)
}
