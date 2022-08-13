package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type User_create struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (request User_create) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/user/create" || r.Method != "POST" {
		return nil
	}

	return nil
}

func (request User_create) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.LoginRegex).MatchString(request.Login) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Password)) {
		return apierror.FieldFormat
	}

	if !database.CheckLoginUnique(request.Login) {
		return apierror.LoginAlreadyExist
	}

	return nil
}

func (request User_create) Do(w http.ResponseWriter) apierror.APIError {
	purpose := user_create_purpose{Login: request.Login, Password: request.Password}
	return process2FAVariablePurpose(w, purpose, request.Login, settings.UserCreate2FA)
}

// purpose when 2FA is activated

type user_create_purpose struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (p user_create_purpose) Do(w http.ResponseWriter) apierror.APIError {
	user := database.User{
		Cache: database.UserCache{
			Login: p.Login}}
	err := user.New(p.Password)
	if err != nil {
		return apierror.InternalServerError
	}

	SetResponse(w, nil, http.StatusOK)
	return nil
}

func (p user_create_purpose) Name() string {
	return "create"
}

func (p user_create_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
