package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_forgot_password struct {
	Login string `json:"login"`
}

func (request *request_forgot_password) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.Conf.Regex.Login).MatchString(request.Login)) {
		return apierror.FieldFormat
	}

	return nil
}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/forgot-password" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_forgot_password
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	user := database.User{String: body.Login}
	err := user.GetId()
	if err != nil {
		ErrorHandler(w, apierror.New(err, "can not find user by login", "Bad Request", 400))
		return
	}

	purpose := token_get_purpose{User_id: user.Uint64}
	process2FAVariablePurpose(w, purpose, body.Login, settings.Conf.Verification.TokenGet)
}
