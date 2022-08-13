package requests

import (
	"encoding/json"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
)

func SetResponse(w http.ResponseWriter, res interface{}, status int) {
	w.WriteHeader(status)
	if res != nil {
		w.Header().Set("Content-Type", "application/json")
		rawbody, err := json.Marshal(res)
		if err != nil {
			ErrorHandler(w, apierror.InternalServerError)
			return
		}
		w.Write(rawbody)
	}
}
