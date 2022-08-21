package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

// user delete body
type request_user_delete struct {
	Access access_part `json:"access"`
}

func (body *request_user_delete) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.Conf.Regex.Token).MatchString(body.Access.Refresh_token) &&
		regexp.MustCompile(settings.Conf.Regex.Password).MatchString(body.Access.Password)) {
		return apierror.FieldFormat
	}

	return nil
}

func User_delete(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/user/delete" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_user_delete
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	var user database.User
	apierr = body.Access.Check(&user)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	purpose := user_delete_purpose{User_id: user.Uint64}
	err := user.GetLogin()
	if err != nil {
		ErrorHandler(w, apierror.New(err, "Can get user's login", "Internal Server Error", 500))
		return
	}
	process2FAVariablePurpose(w, purpose, user.String, settings.Conf.Verification.UserDelete)
}

// purpose when 2FA is activated

type user_delete_purpose struct {
	User_id uint64 `json:"user_id"`
}

func (p user_delete_purpose) Do(w http.ResponseWriter) apierror.APIError {
	// delete user
	user := database.User{Uint64: p.User_id}
	err := user.LogoutEverywhere()
	if err != nil {
		return apierror.New(err, "Can not log out every where for deleting user.", "Internal Server Error", 500)
	}
	err = user.Delete()
	if err != nil {
		return apierror.New(err, "Can not delete user", "Internal Server Error", 500)
	}
	SetResponse(w, nil, http.StatusOK)
	return nil
}

func (p user_delete_purpose) Name() string {
	return "delete"
}
