package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_password_recovery struct {
	Login             string `json:"login"`
	New_password      string `json:"new_password"`
	Logout_everywhere bool   `json:"logout_everywhere"`
}

func (request *request_password_recovery) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.Conf.Regex.Login).MatchString(request.Login) &&
		regexp.MustCompile(settings.Conf.Regex.Password).MatchString(request.New_password)) {
		return apierror.FieldFormat
	}

	return nil
}

func Password_recovery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/password/recovery" || r.Method != "PATCH" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_password_recovery
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

	token := database.Token{}
	refresh_token, err := token.New(user.Uint64)
	if err != nil {
		ErrorHandler(w, apierror.New(err, "can not create token", "Internal Server Error", 500))
		return
	}

	purpose := password_change_purpose{
		User_id:           user.Uint64,
		New_password:      body.New_password,
		Logout_everywhere: false,
		Refresh_token:     refresh_token.String}
	process2FAVariablePurpose(w, purpose, body.Login, settings.Conf.Verification.TokenGet)
}
