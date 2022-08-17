package requests

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func SetResponse(w http.ResponseWriter, res interface{}, status int) {
	w.WriteHeader(status)
	if res != nil {
		w.Header().Set("Content-Type", "application/json")
		rawbody, err := json.Marshal(res)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't marshal response", "Internal Server Error", 500))
			return
		}
		w.Write(rawbody)
	}
}

func ErrorHandler(w http.ResponseWriter, err apierror.APIError) {
	// loging error
	if settings.DebugMode {
		log.Print("Error: ", err.Error(), ", debug: ", err.Debug(), ", status: ", err.Status())
	} else {
		log.Print("Error: ", err.Error())
	}
	SetResponse(w, ErrorBody{Error: err.Msg()}, err.Status())
}

type ErrorBody struct {
	Error string `json:"error"`
}
