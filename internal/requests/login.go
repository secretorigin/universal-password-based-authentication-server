package request

import "net/http"

// /token/get or /login requests
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if req.URL.Path != "/token" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if req.Method == "DELETE" {

	} else if req.Method == "GET" {

	} else if req.Method == "GET" {

	} else if req.Method == "GET" {

	}
}
