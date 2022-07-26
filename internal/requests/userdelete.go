package requests

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
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

	if settings.UserDelete2FA {
		// create temporaty password with purpose 'delete'

	} else {
		// delete user
		UserDelete(&body, &w)
	}
}

func UserDelete(body *request_user_delete_body, w *http.ResponseWriter) {
	// check password and token
	token_body := field.ParseTokenBody(body.Access.Refresh_token)
	if !database.CheckToken(database.DB, body.Access.Refresh_token, int(token_body.Token_id), false) {
		if settings.DebugMode {
			log.Println("Error: Wrong token.")
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}
	if !database.CheckPasswordWithUserId(database.DB, token_body.User_id, body.Access.Password) {
		if settings.DebugMode {
			log.Println("Error: Wrong password.")
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}
	// delete user
	_, err := database.DB.Query("DELETE FROM users WHERE user_id_=$1;", token_body.User_id)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Deleting user from database:", err.Error())
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}

	(*w).WriteHeader(http.StatusOK)
}
