package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Token_update struct {
	Refresh_token string `json:"refresh_token"`
}

func (request Token_update) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/token/update" || r.Method != "PATCH" {
		return apierror.NotFound
	}

	return nil
}

func (request Token_update) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Refresh_token) {
		return apierror.FieldFormat
	}

	return nil
}

func (request Token_update) Do(w http.ResponseWriter) apierror.APIError {
	token_body, err := crypto.ParseToken(request.Refresh_token)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	// check refresh token
	token := database.Token{Cache: database.TokenCache{Id: token_body.Token_id}}
	_, ok, err := token.Check("", request.Refresh_token)
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

	SetResponse(w, tokens, 200)
	return nil
}
