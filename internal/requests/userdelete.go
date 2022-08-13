package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type User_delete struct {
	Access access_part `json:"access"`
}

func (request User_delete) Init(r *http.Request) apierror.APIError {
	if r.URL.Path != "/user/delete" || r.Method != "POST" {
		return apierror.NotFound
	}

	return nil
}

func (request User_delete) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.TokenRegex).MatchString(request.Access.Refresh_token) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Access.Password)) {
		return apierror.FieldFormat
	}

	return nil
}

func (request User_delete) Do(w http.ResponseWriter) apierror.APIError {
	var user database.User
	var token database.Token
	err := CheckAccessPart(request.Access, &token, &user)
	if err != nil {
		return apierror.AuthenticationInfo
	}

	purpose := user_delete_purpose{User_id: user.Cache.Id}
	return process2FAVariablePurpose(w, purpose, user.Cache.Login, settings.UserDelete2FA)
}

// purpose when 2FA is activated

type user_delete_purpose struct {
	User_id uint64 `json:"user_id"`
}

func (p user_delete_purpose) Do(w http.ResponseWriter) apierror.APIError {
	cache := database.UserCache{Id: p.User_id}
	err := cache.Delete()
	if err != nil {
		return apierror.Database
	}
	SetResponse(w, nil, http.StatusOK)
	return nil
}

func (p user_delete_purpose) Name() string {
	return "delete"
}

func (p user_delete_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
