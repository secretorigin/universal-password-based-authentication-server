package requests

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_confirm struct {
	Temporary_token    string `json:"temporary_token"`
	Temporary_password string `json:"temporary_password"`
	Method             string `json:"-"`
}

func (request *request_confirm) Validate() apierror.APIError {
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

func Confirm(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/confirm" || (r.Method != "POST" && r.Method != "PATCH") {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_confirm
	body.Method = r.Method
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	switch r.Method {
	case "POST":
		var login database.Login
		temporary := database.TemporaryToken{String: body.Temporary_token}
		ok, err := temporary.Check(body.Temporary_password, &login)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "can not check temporary password", "Bad Request", 400))
			return
		}
		if !ok {
			ErrorHandler(w, apierror.WrongTempPassword)
			return
		}

		purpose, err := temporary.GetPurpose()

		var p Purpose
		switch purpose.Name {
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
			ErrorHandler(w, apierror.New(err, "Undefined purpose", "Internal Server Error", 500))
			return
		}
		err = json.Unmarshal([]byte(purpose.Data), &p)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "can not unmarshal purpose body", "Internal Server Error", 500))
			return
		}
		p.Do(w)

		// delete old part time password
		err = temporary.Delete()
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't delete temporary password", "Internal Server Error", 500))
			return
		}
	case "PATCH":
		var login database.Login
		temporary := database.TemporaryToken{String: body.Temporary_token}
		ok, err := temporary.Check(body.Temporary_password, &login)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "can not check temporary password", "Bad Request", 400))
			return
		}
		if !ok {
			ErrorHandler(w, apierror.WrongTempToken)
			return
		}

		err = temporary.Update(login)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't update temporary password", "Internal Server Error", 500))
			return
		}
		res := response_confirm_patch{Temporary_token: temporary.String}
		SetResponse(w, res, http.StatusOK)
	default:
		ErrorHandler(w, apierror.NotFound)
	}
}

type response_confirm_patch struct {
	Temporary_token string `json:"temporary_token"`
}
