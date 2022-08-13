package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Token_get struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (request Token_get) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/token/get" || r.Method != "POST" {
		return apierror.NotFound
	}

	return nil
}

func (request Token_get) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.LoginRegex).MatchString(request.Login) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Password)) {
		return apierror.FieldFormat
	}

	return nil
}

func (request Token_get) Do(w http.ResponseWriter) apierror.APIError {
	user := database.User{Cache: database.UserCache{Login: request.Login}}
	ok, err := user.Check(request.Password)
	if err != nil {
		return apierror.InternalServerError
	}
	if !ok {
		return apierror.Password
	}

	purpose := token_get_purpose{User_id: user.Cache.Id}
	return process2FAVariablePurpose(w, purpose, request.Login, settings.TokenGet2FA)
}

type token_get_purpose struct {
	User_id uint64 `json:"user_id"`
}

func (p token_get_purpose) Do(w http.ResponseWriter) apierror.APIError {
	token := database.Token{Cache: database.TokenCache{User_id: p.User_id}}
	tokens, err := token.New()
	if err != nil {
		return apierror.InternalServerError
	}

	SetResponse(w, tokens, http.StatusOK)
	return nil
}

func (p token_get_purpose) Name() string {
	return "token"
}

func (p token_get_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
