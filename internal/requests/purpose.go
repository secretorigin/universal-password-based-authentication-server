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
		verification := database.VerificationToken{}
		err := verification.New(login, purpose.Name(), purpose)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't create verification code", "Internal Server Error", 500))
			return
		}
		SetResponse(w, response_verification_token{Verification_token: verification.String}, http.StatusOK)
	} else {
		apierr := purpose.Do(w)
		if apierr != nil {
			ErrorHandler(w, apierr)
			return
		}
	}
}

type response_verification_token struct {
	Verification_token string `json:"Verification_token"`
}
