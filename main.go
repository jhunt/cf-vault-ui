package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/jhunt/cf-vault-ui/static"
)

func main() {
	failed := false

	url := os.Getenv("VAULT_ADDR")
	if url == "" {
		failed = true
		fmt.Fprintf(os.Stderr, "Missing VAULT_ADDR environment variable (where is your Vault?)\n")
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		failed = true
		fmt.Fprintf(os.Stderr, "Missing VAULT_TOKEN environment variable\n")
	}

	prefix := os.Getenv("VAULT_PREFIX")

	api, err := NewAPI(url, token, prefix)
	if err != nil {
		failed = true
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}

	if failed {
		fmt.Fprintf(os.Stderr, "errors encountered.\n")
		os.Exit(1)
	}

	go api.Background(5)

	http.Handle("/", static.Handler{})
	http.Handle("/v1/", api)
	http.ListenAndServe(":4005", nil)
}
