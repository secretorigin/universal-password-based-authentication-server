package requests

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_confirm_body struct {
	Temporary_token    string `json:"temporary_token"`
	Temporary_password string `json:"temporary_password"`
}

func ConfirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/confirm" || r.Method != "PATCH" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /confirm PATCH:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_confirm_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// check password and token
	token_body := field.ParseTemporaryTokenBody(body.Temporary_token)
	if !database.CheckTemporaryToken(body.Temporary_token, token_body.Temporary_token_id) {
		if settings.DebugMode {
			log.Println("Error: Wrong temporary token.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if !database.CheckTemporaryPassword(body.Temporary_password, token_body.Temporary_token_id) {
		if settings.DebugMode {
			log.Println("Error: Wrong temporary password.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// get data and create response with purpose
	var purpose string
	var data []byte
	err = database.DB.QueryRow("SELECT purpose_, data_ FROM temporary_passwords WHERE temporary_password_id_=$1;",
		token_body.Temporary_token_id).Scan(&purpose, &data)

	if purpose == "create" {
		var stored_body request_user_create_body
		err := json.Unmarshal(data, &stored_body)
		json_error_handler(err, &w)
		UserCreate(&w, &stored_body)
	} else if purpose == "delete" {
		var stored_body user_delete_purpose_body
		err := json.Unmarshal(data, &stored_body)
		json_error_handler(err, &w)
		UserDelete(&w, stored_body)
	} else if purpose == "token" {
		var stored_body token_get_purpose_body
		err := json.Unmarshal(data, &stored_body)
		json_error_handler(err, &w)
		TokenGet(&w, stored_body)
	} else if purpose == "password" {
		var stored_body password_change_purpose_body
		err := json.Unmarshal(data, &stored_body)
		json_error_handler(err, &w)
		PasswordChange(&w, stored_body)
	} else if purpose == "login" {
		var stored_body login_change_purpose_body
		err := json.Unmarshal(data, &stored_body)
		json_error_handler(err, &w)
		LoginChange(&w, stored_body)
	} else {
		if settings.DebugMode {
			log.Println("Error: Wrong purpose in the temporary passwords:", purpose)
		}
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
}

func json_error_handler(err error, w *http.ResponseWriter) {
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(*w, "Server error", http.StatusInternalServerError)
	}
}

// return temporary token
func createPartTimePassword(login string, purpose string, data interface{}) string {
	temporary_password := settings.TemporaryPasswordSend(login) // generate new part time password with custom function
	return database.GenTemporaryPassword(temporary_password, purpose, data)
}
