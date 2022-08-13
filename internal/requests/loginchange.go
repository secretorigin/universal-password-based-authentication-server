package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Login_change struct {
	Access    access_part `json:"access"`
	New_login string      `json:"new_login"`
}

func (request Login_change) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/login/change" || r.Method != "PATCH" {
		return apierror.NotFound
	}

	return nil
}

func (request Login_change) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.TokenRegex).MatchString(request.Access.Refresh_token) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Access.Password) &&
		regexp.MustCompile(settings.LoginRegex).MatchString(request.New_login)) {
		return apierror.FieldFormat
	}

	if !database.CheckLoginUnique(request.New_login) {
		return apierror.LoginAlreadyExist
	}

	return nil
}

func (request Login_change) Do(w http.ResponseWriter) apierror.APIError {
	var user database.User
	var token database.Token
	err := CheckAccessPart(request.Access, &token, &user)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	purpose := login_change_purpose{User_id: user.Cache.Id, New_login: request.New_login}
	process2FAVariablePurpose(w, purpose, request.New_login, settings.UserCreate2FA)
	return nil
}

type login_change_purpose struct {
	User_id   uint64 `json:"user_id"`
	New_login string `json:"new_login"`
}

func (p login_change_purpose) Do(w http.ResponseWriter) apierror.APIError {
	user := database.User{Cache: database.UserCache{Id: p.User_id}}
	err := user.ChangeLogin(p.New_login)
	if err != nil {
		return apierror.InternalServerError
	}

	SetResponse(w, nil, http.StatusOK)
	return nil
}

func (p login_change_purpose) Name() string {
	return "login"
}

func (p login_change_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
