// ATS checker verify if the given path provides acceptable cipher for ATS.
//
// App Transport Security Technote: App Transport Security Technote
// https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/
//
// Usage: ats_checker https://path/to/url
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
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

// check verify ciphers and TLS version
func check(resp *http.Response) (bool, error) {
	if resp.TLS == nil {
		return false, nil
	}
	if resp.TLS.Version != tls.VersionTLS12 {
		return false, nil
	}
	for _, c := range acceptableCipher {
		if resp.TLS.CipherSuite == c {
			return true, nil
		}
	}
	return false, nil
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Println("Usage: ats_checker https://path/to/url")
		os.Exit(0)
	}
	url := flag.Arg(0)
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	if r, err := check(resp); err != nil {
		panic(err)
	} else if r == false {
		log.Printf("%s is not acceptable for ATS\n debug info: %#v\n", url, resp.TLS)
		os.Exit(1)
	}

	log.Printf("%s is acceptable for ATS\n", url)
	os.Exit(0)
}
