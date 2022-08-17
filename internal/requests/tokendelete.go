package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_delete struct {
	Refresh_token string `json:"refresh_token"`
}

func (request *request_token_delete) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Refresh_token) {
		return apierror.FieldFormat
	}

	return nil
}

func Token_delete(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/delete" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_token_delete
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	token := database.Token{String: body.Refresh_token}
	var user database.User
	ok, err := token.Check("refresh", &user.Uint64)
	if err != nil {
		ErrorHandler(w, apierror.CheckToken)
		return
	}
	if !ok {
		ErrorHandler(w, apierror.WrongToken)
		return
	}

	err = token.Delete(body.Refresh_token)
	if err != nil {
		ErrorHandler(w, apierror.New(err, "Can't delete token", "Internal Server Error", 500))
		return
	}

	SetResponse(w, nil, http.StatusOK)
}
