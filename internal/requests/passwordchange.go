package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_password_change struct {
	Access            access_part `json:"access"`
	New_password      string      `json:"new_password"`
	Logout_everywhere bool        `json:"logout_everywhere"`
}

func (request *request_password_change) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.TokenRegex).MatchString(request.Access.Refresh_token) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Access.Password) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.New_password)) {
		return apierror.FieldFormat
	}

	return nil
}

func Password_change(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/password/change" || r.Method != "PATCH" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_password_change
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	var user database.User
	apierr = body.Access.Check(&user)
	if apierr != nil {
		ErrorHandler(w, apierror.Access)
		return
	}
	err := user.GetLogin()
	if err != nil {
		ErrorHandler(w, apierror.New(err, "can not find user by login", "Bad Request", 400))
		return
	}

	purpose := password_change_purpose{
		User_id:           user.Uint64,
		New_password:      body.New_password,
		Logout_everywhere: body.Logout_everywhere,
		Refresh_token:     body.Access.Refresh_token}
	apierr = process2FAVariablePurpose(w, purpose, user.String, settings.PasswordChange2FA)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	SetResponse(w, nil, http.StatusOK)
}

type password_change_purpose struct {
	User_id           uint64 `json:"user_id"`
	New_password      string `json:"new_password"`
	Logout_everywhere bool   `json:"logout_everywhere"`
	Refresh_token     string `json:"refresh_token"`
}

func (p password_change_purpose) Do(w http.ResponseWriter) apierror.APIError {
	// change password
	password := database.Password{String: p.New_password}
	err := password.Change(p.User_id)
	if err != nil {
		return apierror.New(err, "Can't change password", "Internal Server Error", 500)
	}

	// gen new token
	token := database.Token{Uint64: 0}
	refresh_token, err := token.Update(&p.User_id)

	SetResponse(w, response_token_get{
		Token:         token.String,
		Refresh_token: refresh_token.String,
	}, http.StatusOK)
	return nil
}

func (p password_change_purpose) Name() string {
	return "password"
}

func (p password_change_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
