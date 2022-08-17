package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_login_change struct {
	Access    access_part `json:"access"`
	New_login string      `json:"new_login"`
}

func (request *request_login_change) Validate() apierror.APIError {
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

func Login_change(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login/change" || r.Method != "PATCH" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_login_change
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

	purpose := login_change_purpose{User_id: user.Uint64, New_login: body.New_login}
	apierr = process2FAVariablePurpose(w, purpose, body.New_login, settings.UserCreate2FA)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}
	return
}

type login_change_purpose struct {
	User_id   uint64 `json:"user_id"`
	New_login string `json:"new_login"`
}

func (p login_change_purpose) Do(w http.ResponseWriter) apierror.APIError {
	login := database.Login{String: p.New_login}
	err := login.Change(p.User_id)
	if err != nil {
		return apierror.New(err, "Can't change login", "Internal Server Error", 500)
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
