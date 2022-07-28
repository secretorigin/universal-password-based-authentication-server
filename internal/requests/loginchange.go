package requests

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_login_change_body struct {
	Access    access_body_part `json:"access"`
	New_login string           `json:"new_login"`
}

// /user/create or /register request handler
func LoginChangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login/change" || r.Method != "PATCH" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /login/change PATCH:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_login_change_body
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
	if regexp.MustCompile(settings.TokenRegex).MatchString(body.Access.Refresh_token) ||
		regexp.MustCompile(settings.PasswordRegex).MatchString(body.Access.Password) ||
		regexp.MustCompile(settings.LoginRegex).MatchString(body.New_login) {
		if settings.DebugMode {
			log.Println("Error: Fields does not match regexp.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// check access part
	token_body, check := database.CheckAccessPart(body.Access.Refresh_token, body.Access.Password)
	if !check {
		if settings.DebugMode {
			log.Println("Error: Wrong access part.")
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if settings.PasswordChange2FA {
		// create temporaty password with purpose 'login'
		var res response_temporary_token_body
		// send temporary token with new login
		res.Temporary_token = createPartTimePassword(body.New_login, "login", login_change_purpose_body{
			User_id:   token_body.User_id,
			New_login: body.New_login})
		writeResponse(&w, res)
	} else {
		// cahnge password
		LoginChange(&w, login_change_purpose_body{
			User_id:   token_body.User_id,
			New_login: body.New_login})
	}
}

func LoginChange(w *http.ResponseWriter, data login_change_purpose_body) {
	_, err := database.DB.Query("UPDATE users SET login_=$1 WHERE user_id_=$2;",
		data.New_login, data.User_id)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Inserting new login in database:", err.Error())
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}

	(*w).WriteHeader(http.StatusOK)
}
