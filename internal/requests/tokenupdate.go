package requests

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_update_body struct {
	Refresh_token string `json:"refresh_token"`
}

type response_token_update_body struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}

// /user/create or /register request handler
func TokenUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/update" || r.Method != "PATCH" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /token/update PATCH:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_token_update_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	token_body := field.ParseTokenBody(body.Refresh_token)
	var res response_token_update_body
	res.Token, res.Refresh_token = database.UpdateToken(body.Refresh_token,
		token_body.User_id, token_body.Token_id)

	writeResponse(&w, res)
}
