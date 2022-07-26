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

type request_user_create_body struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// /user/create or /register request handler
func UserCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/user/create" || r.Method != "POST" {
		if settings.DebugMode {
			log.Println("Error: Wrong url for /user/create POST:", r.URL.Path, r.Method)
		}
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// get data from request
	var body request_user_create_body
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		if settings.DebugMode {
			log.Println("Error: Can not decode requests body:", err.Error())
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if settings.UserCreate2FA {
		// create temporaty password with purpose 'login'

	} else {
		// create new user
		UserCreate(&body, &w)
	}
}

func UserCreate(body *request_user_create_body, w *http.ResponseWriter) {
	// gen new random parameters and hash using them
	iterations := rand.Int31()%1000 + settings.PASSWORD_MIN_ITERATIONS_COUNT
	hash := field.HashPassword(field.GenSalt(settings.PASSWORD_SALT_SIZE), []byte(body.Password), int(iterations))
	// write in database
	_, err := database.DB.Query("INSERT INTO users (login_, password_hash_, password_iterations_) VALUES "+
		"($1, $2, $3);", body.Login, hex.EncodeToString(hash), iterations)
	if err != nil {
		log.Println(err.Error())
		if settings.DebugMode {
			log.Println("Error: Inserting new user in database:", err.Error())
		}
		http.Error(*w, "Bad request", http.StatusBadRequest)
		return
	}

	(*w).WriteHeader(http.StatusOK)
}
