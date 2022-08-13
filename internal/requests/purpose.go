package requests

import (
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
)

type Purpose interface {
	Do(w http.ResponseWriter) apierror.APIError
	Name() string
	Encode() []byte
}

func process2FAVariablePurpose(w http.ResponseWriter, purpose Purpose, login string, twofa bool) apierror.APIError {
	if twofa {
		temporary := database.TemporaryPassword{
			Cache: database.TemporaryPasswordCache{},
			Purpose: database.PurposeCache{
				Purpose: purpose.Name(),
				Data:    purpose.Encode()}}

		token, err := temporary.New(login)
		if err != nil {
			return apierror.InternalServerError
		}

		SetResponse(w, response_temporary_token_body{Temporary_token: token}, 200)
		return nil
	} else {
		return purpose.Do(w)
	}
}
