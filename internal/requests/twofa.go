package requests

import (
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
)

type request_twofa struct {
	Access access_part `json:"access"`
}

func (request *request_twofa) Validate() apierror.APIError {
	return nil
}

func Twofa(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/twofa" || r.Method != "PATCH" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_twofa
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	var user database.User
	apierr = body.Access.Check(&user)
	if apierr != nil {
		ErrorHandler(w, apierror.Access)
		return
	}

	user.TwoFA()
}
