package requests

import (
	"encoding/json"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
)

func Handler(servehttp func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		servehttp(w, r)
	}
}

type request_body interface {
	Validate() apierror.APIError
}

func parseRequestBody(r *http.Request, body request_body) apierror.APIError {
	err := json.NewDecoder(r.Body).Decode(body)
	if err != nil {
		return apierror.BodyDecode
	}
	defer r.Body.Close()

	apierr := body.Validate()
	return apierr
}

type access_part struct {
	Refresh_token string `json:"refresh_token"`
	Password      string `json:"password"`
}

func (access access_part) Check(user *database.User) apierror.APIError {
	token := database.Token{String: access.Refresh_token}
	ok, err := token.Check("refresh", &user.Uint64)
	if err != nil {
		return apierror.ParseToken
	}
	if !ok {
		return apierror.WrongToken
	}

	// check password
	password := database.Password{String: access.Password}
	ok, err = password.Check(database.User{Uint64: user.Uint64})
	if err != nil {
		return apierror.CheckPassword
	}
	if !ok {
		return apierror.WrongPassword
	}

	return nil
}
