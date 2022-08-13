package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Password_change struct {
	Access            access_part `json:"access"`
	New_password      string      `json:"new_password"`
	Logout_everywhere bool        `json:"logout_everywhere"`
}

func (request Password_change) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/password/change" || r.Method != "PATCH" {
		return apierror.NotFound
	}

	return nil
}

func (request Password_change) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.TokenRegex).MatchString(request.Access.Refresh_token) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Access.Password) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.New_password)) {
		return apierror.FieldFormat
	}

	return nil
}

func (request Password_change) Do(w http.ResponseWriter) apierror.APIError {
	var user database.User
	var token database.Token
	err := CheckAccessPart(request.Access, &token, &user)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	purpose := password_change_purpose{
		User_id:           user.Cache.Id,
		New_password:      request.New_password,
		Logout_everywhere: request.Logout_everywhere,
		Refresh_token:     request.Access.Refresh_token}
	return process2FAVariablePurpose(w, purpose, user.Cache.Login, settings.PasswordChange2FA)
}

type password_change_purpose struct {
	User_id           uint64 `json:"user_id"`
	New_password      string `json:"new_password"`
	Logout_everywhere bool   `json:"logout_everywhere"`
	Refresh_token     string `json:"refresh_token"`
}

func (p password_change_purpose) Do(w http.ResponseWriter) apierror.APIError {
	user := database.User{Cache: database.UserCache{Id: p.User_id}}
	err := user.ChangePassword(p.New_password)
	if err != nil {
		return apierror.InternalServerError
	}

	token_body, err := crypto.ParseToken(p.Refresh_token)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	// check refresh token
	token := database.Token{Cache: database.TokenCache{Id: token_body.Token_id}}
	_, ok, err := token.Check("", p.Refresh_token)
	if err != nil {
		return apierror.AuthenticationInfo
	}
	if !ok {
		return apierror.AuthenticationInfo
	}

	// update tokens
	tokens, err := token.UpdateToken()
	if err != nil {
		return apierror.InternalServerError
	}

	// delete all tokens if it's required
	if p.Logout_everywhere {
		err = user.LogoutEverywhere(token.Cache.Id)
		if err != nil {
			return apierror.InternalServerError
		}
	}

	SetResponse(w, tokens, http.StatusOK)
	return nil
}

func (p password_change_purpose) Name() string {
	return "password"
}

func (p password_change_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
