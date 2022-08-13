package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Token_check struct {
	Token string `json:"token"`
}

func (request Token_check) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/token/check" || r.Method != "POST" {
		return apierror.NotFound
	}

	return nil
}

func (request Token_check) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Token) {
		return apierror.FieldFormat
	}

	return nil
}

func (request Token_check) Do(w http.ResponseWriter) apierror.APIError {
	token_body, err := crypto.ParseToken(request.Token)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	token := database.Token{Cache: database.TokenCache{Id: token_body.Token_id}}
	ok, _, err := token.Check(request.Token, "")
	if err != nil {
		return apierror.InternalServerError
	}
	if !ok {
		return apierror.AuthenticationInfo
	}

	SetResponse(w, nil, http.StatusOK)

	return nil
}
