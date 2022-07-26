package requests

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_get_body struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type response_token_get_body struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}

// /user/create or /register request handler
func TokenGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/get" || r.Method != "POST" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /token/get POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_token_get_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if settings.TokenGet2FA {
		// create temporaty password with purpose 'login'

	} else {
		// generate new token for user
		TokenGet(&body, &w)
	}
}

func TokenGet(body *request_token_get_body, w *http.ResponseWriter) {
	var user_id uint64
	err := database.DB.QueryRow("SELECT user_id_ FROM users WHERE login_=$1;", body.Login).Scan(&user_id)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Println(err.Error())
		} else if settings.DebugMode {
			log.Println("Error: User not found:", err.Error())
		}
		http.Error(*w, "Bad request", 400)
		return
	}
	// check password
	if !database.CheckPasswordWithUserId(database.DB, user_id, body.Password) {
		http.Error(*w, "Bad request", 400)
		if settings.DebugMode {
			log.Println("Error: Wrong password.")
		}
		return
	}

	var res response_token_get_body
	res.Token, res.Refresh_token = database.GenToken(database.DB, user_id)
	if res.Token == "" || res.Refresh_token == "" {
		http.Error(*w, "Bad request", 400)
		if settings.DebugMode {
			log.Println("Error: creating token.")
		}
		return
	}

	(*w).WriteHeader(http.StatusOK)
	(*w).Header().Set("Content-Type", "application/json")
	rawbody, err := json.Marshal(res)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: creating response body.")
		}
		http.Error(*w, "Bad request", 400)
		return
	}
	(*w).Write(rawbody)
}
