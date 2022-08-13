package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Confirm struct {
	Temporary_token    string `json:"temporary_token"`
	Temporary_password string `json:"temporary_password"`
	Method             string `json:"-"`
}

func (request Confirm) Init(r *http.Request) apierror.APIError {
	request.Method = r.Method

	if r.URL.Path != "/confirm" || (r.Method != "POST" && r.Method != "PATCH") {
		return apierror.NotFound
	}

	return nil
}

func (request Confirm) Validate() apierror.APIError {
	switch request.Method {
	case "POST":
		if !(regexp.MustCompile(settings.TokenRegex).MatchString(request.Temporary_token) &&
			regexp.MustCompile(settings.TemporaryPasswordRegex).MatchString(request.Temporary_password)) {
			return apierror.FieldFormat
		}
	case "PATCH":
		if !regexp.MustCompile(settings.TokenRegex).MatchString(request.Temporary_token) {
			return apierror.FieldFormat
		}
	}

	return nil
}

func (request Confirm) Do(w http.ResponseWriter) apierror.APIError {
	switch request.Method {
	case "POST":
		token_body, err := crypto.ParseTemporaryToken(request.Temporary_token)
		if err != nil {
			return apierror.AuthenticationInfo
		}
		tpass := database.TemporaryPassword{
			Cache: database.TemporaryPasswordCache{
				Id: token_body.Temporary_token_id}}
		tokenok, passwordok, err := tpass.Check(request.Temporary_token, request.Temporary_password)
		if err != nil {
			return apierror.AuthenticationInfo
		}
		if !tokenok || !passwordok {
			return apierror.AuthenticationInfo
		}

		// get data and create response with purpose
		pcache := database.PurposeCache{Id: tpass.Cache.Purpose_id}
		err = pcache.Select()
		if err != nil {
			return apierror.InternalServerError
		}

		var p Purpose
		switch pcache.Purpose {
		case "create":
			p = user_create_purpose{}
		case "delete":
			p = user_delete_purpose{}
		case "token":
			p = token_get_purpose{}
		case "password":
			p = password_change_purpose{}
		case "login":
			p = login_change_purpose{}
		default:
			return apierror.InternalServerError
		}
		err = json.Unmarshal(pcache.Data, &p)
		if err != nil {
			return apierror.InternalServerError
		}
		p.Do(w)

		// delete old part time password
		_, err = database.GetDB().Query("DELETE FROM temporary_passwords WHERE temporary_password_id_=$1;",
			token_body.Temporary_token_id)
		if err != nil {
			return apierror.InternalServerError
		}
		return nil
	case "PATCH":
		token_body, err := crypto.ParseTemporaryToken(request.Temporary_token)
		if err != nil {
			return apierror.AuthenticationInfo
		}
		tpass := database.TemporaryPassword{
			Cache: database.TemporaryPasswordCache{
				Id: token_body.Temporary_token_id}}
		tokenok, passwordok, err := tpass.Check(request.Temporary_token, "")
		if err != nil {
			return apierror.AuthenticationInfo
		}
		if !tokenok || !passwordok {
			return apierror.AuthenticationInfo
		}

		token, err := tpass.Update(token_body.Login)
		if err != nil {
			return apierror.InternalServerError
		}
		res := response_confirm_patch{Temporary_token: token}
		SetResponse(w, res, http.StatusOK)
		return nil
	default:
		return apierror.InternalServerError
	}
}

type response_confirm_patch struct {
	Temporary_token string `json:"temporary_token"`
}
