package requests

import (
	"fmt"
	"net/http"
)

// /token/get or /login requests
func UserCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/user/create" || r.Method != "POST" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "<h1>Hey!</h1>")
}
