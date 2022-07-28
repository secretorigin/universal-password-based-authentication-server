package requests

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_check_body struct {
	Token string `json:"token"`
}

// /user/create or /register request handler
func TokenCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/check" || r.Method != "POST" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /token/check POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_token_check_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	//check fields
	if regexp.MustCompile(settings.TOKEN_REGEX).MatchString(body.Token) {
		if settings.DebugMode {
			log.Println("Error: Fields does not match regexp.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	token_body := field.ParseTokenBody(body.Token)
	if database.CheckToken(body.Token, token_body.Token_id, true) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}
