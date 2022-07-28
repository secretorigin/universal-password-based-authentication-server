package requests

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_user_delete_body struct {
	Access access_body_part `json:"access"`
}

// /user/delete request handler
func UserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/user/delete" || r.Method != "POST" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /user/delete POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_user_delete_body
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
		regexp.MustCompile(settings.PasswordRegex).MatchString(body.Access.Password) {
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

	if settings.UserDelete2FA {
		// create temporaty password with purpose 'delete'
		var login string
		err = database.DB.QueryRow("SELECT login_ FROM users WHERE user_id_=$1;", token_body.User_id).Scan(&login)
		if err != nil {
			log.Println(err.Error())
			if settings.DebugMode {
				log.Println("Error: Getting user's login from database:", err.Error())
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var res response_temporary_token_body
		res.Temporary_token = createPartTimePassword(login, "delete", user_delete_purpose_body{
			User_id: token_body.User_id})
		writeResponse(&w, res)
	} else {
		// delete user
		UserDelete(&w, user_delete_purpose_body{User_id: token_body.User_id})
	}
}

func UserDelete(w *http.ResponseWriter, body user_delete_purpose_body) {
	// delete user
	_, err := database.DB.Query("DELETE FROM users WHERE user_id_=$1;", body.User_id)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Deleting user from database:", err.Error())
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}

	_, err = database.GetDB().Query("DELETE FROM tokens WHERE user_id_=$1;", body.User_id)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Deleting tokens in database:", err.Error())
		}
		// where is not error for user, because it must understand that user deleted
	}

	(*w).WriteHeader(http.StatusOK)
}
