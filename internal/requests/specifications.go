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

	SetResponse(w, response_specifications{
		DebugMode:    settings.Conf.DebugMode,
		Verification: settings.Conf.Verification,
		Regex:        settings.Conf.Regex,
		InviteCode:   settings.Conf.Security.InviteCode,
	}, http.StatusOK)
}

type response_specifications struct {
	DebugMode    bool `json:"debug-mode"`
	Verification struct {
		PasswordChange bool `json:"password-change"`
		LoginChange    bool `json:"login-change"`
		UserCreate     bool `json:"user-create"`
		UserDelete     bool `json:"user-delete"`
		TokenGet       bool `json:"token-get"`
	} `json:"verification"`
	Regex struct {
		VerificationCode string `json:"verification-code"`
		InviteCode       string `json:"invite-code"`
		Login            string `json:"login"`
		Password         string `json:"password"`
		Token            string `json:"token"`
	} `json:"regex"`
	InviteCode bool `json:"invite-code"`
}
