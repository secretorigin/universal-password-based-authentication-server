package requests

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_password_change_body struct {
	Access            access_body_part `json:"access"`
	New_password      string           `json:"new_password"`
	Logout_everywhere bool             `json:"logout_everywhere"`
}

type response_password_change_body struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}

// /user/create or /register request handler
func PasswordChangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/password/change" || r.Method != "PATCH" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /password/change PATCH:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_password_change_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
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
		// create temporaty password with purpose 'password'
		// get login
		var login string
		err = database.DB.QueryRow("SELECT login_ FROM users WHERE user_id_=$1;", token_body.User_id).Scan(&login)
		if err != nil {
			if settings.DebugMode {
				log.Println("Error: Can not find user:", err.Error())
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var res response_temporary_token_body
		res.Temporary_token = createPartTimePassword(login, "password", password_change_purpose_body{
			User_id:           token_body.User_id,
			New_password:      body.New_password,
			Logout_everywhere: body.Logout_everywhere,
			Refresh_token:     body.Access.Refresh_token})
		writeResponse(&w, res)
	} else {
		// cahnge password
		PasswordChange(&w, password_change_purpose_body{
			User_id:           token_body.User_id,
			New_password:      body.New_password,
			Logout_everywhere: body.Logout_everywhere,
			Refresh_token:     body.Access.Refresh_token})
	}
}

func PasswordChange(w *http.ResponseWriter, data password_change_purpose_body) {
	iterations := rand.Int31()%1000 + settings.PASSWORD_MIN_ITERATIONS_COUNT
	hash := field.HashPassword(field.GenSalt(settings.PASSWORD_SALT_SIZE), []byte(data.New_password), int(iterations))
	_, err := database.DB.Query("UPDATE users SET password_hash_=$1, password_iterations_=$2 WHERE user_id_=$3;",
		hex.EncodeToString(hash), iterations, data.User_id)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Inserting new password in database:", err.Error())
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}

	// delete all tokens if it's required
	if data.Logout_everywhere {
		_, err := database.DB.Query("DELETE FROM tokens WHERE user_id_=$1;", data.User_id)
		if err != nil {
			log.Println(err.Error())
			if settings.DebugMode {
				log.Println("Error: Deleting tokens in database:", err.Error())
			}
			// where is not error for user, because it must understand that password changes
		}
	}

	// generate new token for user
	token_body := field.ParseTokenBody(data.Refresh_token)
	var res response_password_change_body
	res.Token, res.Refresh_token = database.UpdateToken(data.Refresh_token,
		token_body.User_id, token_body.Token_id)
	writeResponse(w, res)
}
