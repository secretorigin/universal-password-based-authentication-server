package requests

import (
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func ErrorHandler(w http.ResponseWriter, err apierror.APIError) {
	// loging error
	log.Println("Error:", err.Error())
	if settings.DebugMode {
		log.Println("Error: Can not decode requests body:", err.Error())
	}
	SetResponse(w, ErrorBody{Error: err.Error()}, err.Status())
}

type ErrorBody struct {
	Error string `json:"error"`
}
