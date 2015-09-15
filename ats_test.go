package main

import (
	"net/http"
	"testing"
)

func testCheckingTLS(t *testing.T) {
	if b, err := check(&http.Response{TLS:nil}); err != nil {
		t.Fatalf("checker failed %s", err)
	} else if b == true {
		t.Fatal("checker passed despite of tls is nil\n")
	}
}
