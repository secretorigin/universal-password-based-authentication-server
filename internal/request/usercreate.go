package request

import (
	"fmt"
	"net/http"
)

// /token/get or /login requests
func userCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != "POST" {
		return
	}

	fmt.Fprintf(w, "<h1>Hey!</h1>")
}
