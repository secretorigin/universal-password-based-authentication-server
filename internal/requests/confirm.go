package requests

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_confirm struct {
	Verification_token string `json:"verification_token"`
	Verification_code  string `json:"verification_code"`
	Method             string `json:"-"`
}

func (request *request_confirm) Validate() apierror.APIError {
	switch request.Method {
	case "POST":
		if !(regexp.MustCompile(settings.Conf.Regex.Token).MatchString(request.Verification_token) &&
			regexp.MustCompile(settings.Conf.Regex.VerificationCode).MatchString(request.Verification_code)) {
			return apierror.FieldFormat
		}
	case "PATCH":
		if !regexp.MustCompile(settings.Conf.Regex.Token).MatchString(request.Verification_token) {
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
	var login database.Login
	verification := database.VerificationToken{String: body.Verification_token}
	ok, err := verification.Check(body.Verification_code, &login)
	if err != nil {
		ErrorHandler(w, apierror.New(err, "can not check verification code", "Bad Request", 400))
		return
	}
	if !ok {
		ErrorHandler(w, apierror.WrongVerificationCode)
		return
	}

	switch r.Method {
	case "POST":
		purpose, err := verification.GetPurpose()

		var p Purpose
		switch purpose.Name {
		case "create":
			p = &user_create_purpose{}
		case "delete":
			p = &user_delete_purpose{}
		case "token":
			p = &token_get_purpose{}
		case "password":
			p = &password_change_purpose{}
		case "login":
			p = &login_change_purpose{}
		default:
			ErrorHandler(w, apierror.New(err, "Undefined purpose", "Internal Server Error", 500))
			return
		}
		err = json.Unmarshal([]byte(purpose.Data), p)
		if err != nil {
			ErrorHandler(w, apierror.New(err, "can not unmarshal purpose body", "Internal Server Error", 500))
			return
		}
		p.Do(w)

		// delete old part time password
		err = verification.Delete()
		if err != nil {
			ErrorHandler(w, apierror.New(err, "Can't delete verification code", "Internal Server Error", 500))
			return
		}
	case "PATCH":
		//check time
		resend_waiting_time := time.Duration(
			uint32(math.Pow(
				float64(settings.Conf.Security.Verification.ResendTimeCoefficient),
				float64(verification.Resended)),
			)*settings.Conf.Security.Time.Resend) * time.Second
		if !crypto.TimePassed(time.Unix(verification.Creation_date, 0), resend_waiting_time) {
			ErrorHandler(w, apierror.New(nil, "can not resend in this time", "Unavailable Resend", 400))
			return
		}

		err = verification.Update(login)
		if err != nil {
			if err.Error() == "impossible resending" {
				ErrorHandler(w, apierror.New(err, "awailable resend count is 0", "Token dies", 400))
				return
			} else {
				ErrorHandler(w, apierror.New(err, "Can't update verification code", "Internal Server Error", 500))
				return
			}
		}
		res := response_confirm_patch{Verification_token: verification.String}
		SetResponse(w, res, http.StatusOK)
	default:
		ErrorHandler(w, apierror.NotFound)
	}
}

type response_confirm_patch struct {
	Verification_token string `json:"verification_token"`
}
