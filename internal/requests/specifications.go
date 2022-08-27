package requests

import (
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func Specifications(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/specifications" || r.Method != "GET" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	SetResponse(w, settings.Conf, http.StatusOK)
}
