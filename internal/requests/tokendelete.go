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

type request_token_delete_body struct {
	Refresh_token string `json:"refresh_token"`
}

// /user/create or /register request handler
func TokenDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/delete" || r.Method != "POST" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /token/delete POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_token_delete_body
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
	if !regexp.MustCompile(settings.TokenRegex).MatchString(body.Refresh_token) {
		if settings.DebugMode {
			log.Println("Error: Fields does not match regexp.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	token_body := field.ParseTokenBody(body.Refresh_token)
	if !database.CheckToken(body.Refresh_token, token_body.Token_id, false) {
		if settings.DebugMode {
			log.Println("Error: Wrong token.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// delete token and logout from this device
	database.DB.Query("DELETE FROM tokens WHERE token_id_=$1;", token_body.Token_id)
}
