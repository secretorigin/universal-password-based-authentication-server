package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_check struct {
	Token string `json:"token"`
}

func (request *request_token_check) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Token) {
		return apierror.FieldFormat
	}

	return nil
}

func Token_check(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/check" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_token_check
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	token := database.Token{String: body.Token}
	var user database.User
	ok, err := token.Check("token", &user.Uint64)
	if err != nil {
		ErrorHandler(w, apierror.CheckToken)
		return
	}
	if !ok {
		ErrorHandler(w, apierror.WrongToken)
		return
	}

	SetResponse(w, nil, http.StatusOK)
}
