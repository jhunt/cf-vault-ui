package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func ok(m string) interface{} {
	return struct {
		OK string `json:"ok"`
	}{
		OK: m,
	}
}

func oops(code int, w http.ResponseWriter, err error) {
	in := struct {
		Error string `json:"error"`
	}{
		Error: fmt.Sprintf("%s", err),
	}
	b, err := json.Marshal(in)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, `{"error":"an unknown error occurred"}`+"\n")
		return
	}

	w.WriteHeader(code)
	fmt.Fprintf(w, "%s\n", string(b))
}

func reply(code int, w http.ResponseWriter, what interface{}) {
	b, err := json.Marshal(what)
	if err != nil {
		oops(500, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, "%s\n", string(b))
}

func has(haystack interface{}, needle string) bool {
	m := haystack.(map[string]string)
	_, ok := m[needle]
	return ok
}
