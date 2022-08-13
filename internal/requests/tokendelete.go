package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Token_delete struct {
	Refresh_token string `json:"refresh_token"`
}

func (request Token_delete) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/token/delete" || r.Method != "POST" {
		return apierror.NotFound
	}

	return nil
}

func (request Token_delete) Validate() apierror.APIError {
	if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Refresh_token) {
		return apierror.FieldFormat
	}

	return nil
}

func (request Token_delete) Do(w http.ResponseWriter) apierror.APIError {
	token_body, err := crypto.ParseToken(request.Refresh_token)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	token := database.Token{Cache: database.TokenCache{Id: token_body.Token_id}}
	_, ok, err := token.Check("", request.Refresh_token)
	if err != nil {
		return apierror.InternalServerError
	}
	if !ok {
		return apierror.AuthenticationInfo
	}

	err = token.Cache.Delete()
	if err != nil {
		return apierror.InternalServerError
	}

	SetResponse(w, nil, http.StatusOK)

	return nil
}
