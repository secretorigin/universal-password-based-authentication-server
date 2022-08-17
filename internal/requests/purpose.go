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

func process2FAVariablePurpose(w http.ResponseWriter, purpose Purpose, login string, twofa bool) {
	if twofa {
		temporary := database.TemporaryToken{}
		err := temporary.New(login, purpose.Name(), purpose)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't create temporary password", "Internal Server Error", 500))
			return
		}
		SetResponse(w, response_temporary_token{Temporary_token: temporary.String}, http.StatusOK)
	} else {
		apierr := purpose.Do(w)
		if apierr != nil {
			ErrorHandler(w, apierr)
			return
		}
	}
}

type response_temporary_token struct {
	Temporary_token string `json:"temporary_token"`
}
