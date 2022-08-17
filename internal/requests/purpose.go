package requests

import (
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
)

type Purpose interface {
	Do(w http.ResponseWriter) apierror.APIError
	Name() string
}

func process2FAVariablePurpose(w http.ResponseWriter, purpose Purpose, login string, twofa bool) (response_temporary_token, apierror.APIError) {
	if twofa {
		temporary := database.TemporaryToken{}
		err := temporary.New(login, purpose.Name(), purpose)
		if err != nil {
			return response_temporary_token{}, apierror.New(err, "Can't create temporary password", "Internal Server Error", 500)
		}

		return response_temporary_token{Temporary_token: temporary.String}, nil
	} else {
		return response_temporary_token{}, purpose.Do(w)
	}
}

type response_temporary_token struct {
	Temporary_token string `json:"temporary_token"`
}
