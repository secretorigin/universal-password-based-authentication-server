package requests

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type access_body_part struct {
	Refresh_token string `json:"refresh_token"`
	Password      string `json:"password"`
}

type response_temporary_token_body struct {
	Temporary_token string `json:"temporary_token"`
}

func writeResponse(w *http.ResponseWriter, res interface{}) {
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

// purpose bodies for 2FA

type user_delete_purpose_body struct {
	User_id uint64 `json:"user_id"`
}

type token_get_purpose_body struct {
	User_id uint64 `json:"user_id"`
}

type password_change_purpose_body struct {
	User_id           uint64 `json:"user_id"`
	New_password      string `json:"new_password"`
	Logout_everywhere bool   `json:"logout_everywhere"`
	Refresh_token     string `json:"refresh_token"`
}

type login_change_purpose_body struct {
	User_id   uint64 `json:"user_id"`
	New_login string `json:"new_login"`
}
