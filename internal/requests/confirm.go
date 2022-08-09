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

type request_confirm_post_body struct {
	Temporary_token    string `json:"temporary_token"`
	Temporary_password string `json:"temporary_password"`
}

func (r *request_confirm_post_body) Validate() bool {
	return (regexp.MustCompile(settings.TokenRegex).MatchString(r.Temporary_token) &&
		regexp.MustCompile(settings.TemporaryPasswordRegex).MatchString(r.Temporary_password))
}

type request_confirm_patch_body struct {
	Temporary_token string `json:"temporary_token"`
}

func (r *request_confirm_patch_body) Validate() bool {
	return regexp.MustCompile(settings.TokenRegex).MatchString(r.Temporary_token)
}

type response_confirm_patch_body struct {
	Temporary_token string `json:"temporary_token"`
}

func ConfirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/confirm" || (r.Method != "POST" && r.Method != "PATCH") {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /confirm POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method == "POST" {
		// confirm action
		confirmPost(w, r)
	} else if r.Method == "PATCH" {
		// resend code
		confirmPatch(w, r)
	}
}

func confirmPatch(w http.ResponseWriter, r *http.Request) {
	// get data from request
	var body request_confirm_patch_body
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
	if !body.Validate() {
		if settings.DebugMode {
			log.Println("Error: Fields does not match regexp.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// check token
	token_body := field.ParseTemporaryTokenBody(body.Temporary_token)
	if !database.CheckTemporaryToken(body.Temporary_token, token_body.Temporary_token_id) {
		if settings.DebugMode {
			log.Println("Error: Wrong temporary token.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	temporary_password := settings.TemporaryPasswordSend(token_body.Login)
	token := database.UpdateTemporaryPassword(
		temporary_password,
		token_body.Login,
		token_body.Temporary_token_id)
	res := response_confirm_patch_body{
		Temporary_token: token}

	writeResponse(&w, res)
}

func confirmPost(w http.ResponseWriter, r *http.Request) {
	// get data from request
	var body request_confirm_post_body
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
	if !body.Validate() {
		if settings.DebugMode {
			log.Println("Error: Fields does not match regexp.")
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
	err = database.GetDB().QueryRow("SELECT purpose_, data_ FROM temporary_passwords WHERE temporary_password_id_=$1;",
		token_body.Temporary_token_id).Scan(&purpose, &data)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not select temporary password data:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if purpose == "create" {
		var stored_body request_user_create_body
		err := json.Unmarshal(data, &stored_body)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not decode requests body:", err.Error())
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		UserCreate(&w, &stored_body)
	} else if purpose == "delete" {
		var stored_body user_delete_purpose_body
		err := json.Unmarshal(data, &stored_body)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not decode requests body:", err.Error())
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		UserDelete(&w, stored_body)
	} else if purpose == "token" {
		var stored_body token_get_purpose_body
		err := json.Unmarshal(data, &stored_body)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not decode requests body:", err.Error())
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		TokenGet(&w, stored_body)
	} else if purpose == "password" {
		var stored_body password_change_purpose_body
		err := json.Unmarshal(data, &stored_body)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not decode requests body:", err.Error())
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		PasswordChange(&w, stored_body)
	} else if purpose == "login" {
		var stored_body login_change_purpose_body
		err := json.Unmarshal(data, &stored_body)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not decode requests body:", err.Error())
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		LoginChange(&w, stored_body)
	} else {
		if settings.DebugMode {
			log.Println("Error: Wrong purpose in the temporary passwords:", purpose)
		}
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// delete old part time password
	_, err = database.GetDB().Query("DELETE FROM temporary_passwords WHERE temporary_password_id_=$1;",
		token_body.Temporary_token_id)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not delete temporary password:", err.Error())
		}
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
}

// return temporary token
func createPartTimePassword(login string, purpose string, data interface{}) string {
	temporary_password := settings.TemporaryPasswordSend(login) // generate new part time password with custom function
	return database.GenTemporaryPassword(temporary_password, purpose, login, data)
}
