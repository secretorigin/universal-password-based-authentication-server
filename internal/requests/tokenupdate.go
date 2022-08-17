package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_update struct {
	Refresh_token string `json:"refresh_token"`
}

func (request *request_token_update) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Refresh_token) {
		return apierror.FieldFormat
	}

	return nil
}

func Token_update(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/update" || r.Method != "PATCH" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_token_update
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

	refresh_token, err := token.Update(&user.Uint64)
	if err != nil {
		ErrorHandler(w, apierror.New(err, "Can't update token", "Internal Server Error", 500))
		return
	}

	SetResponse(w, response_token_get{
		Token:         token.String,
		Refresh_token: refresh_token.String,
	}, http.StatusOK)
}
