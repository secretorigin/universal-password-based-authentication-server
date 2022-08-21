package requests

import (
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_token_get struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (request *request_token_get) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.Conf.Regex.Login).MatchString(request.Login) &&
		regexp.MustCompile(settings.Conf.Regex.Password).MatchString(request.Password)) {
		return apierror.FieldFormat
	}

	return nil
}

func Token_get(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token/get" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_token_get
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	user := database.User{String: body.Login}
	err := user.GetId()
	if err != nil {
		ErrorHandler(w, apierror.New(err, "can not find user by login", "Bad Request", 400))
		return
	}
	password := database.Password{String: body.Password}
	ok, err := password.Check(user)
	if err != nil {
		ErrorHandler(w, apierror.CheckPassword)
		return
	}
	if !ok {
		ErrorHandler(w, apierror.WrongPassword)
		return
	}

	purpose := token_get_purpose{User_id: user.Uint64}
	process2FAVariablePurpose(w, purpose, body.Login, settings.Conf.Verification.TokenGet)
}

type token_get_purpose struct {
	User_id uint64 `json:"user_id"`
}

func (p token_get_purpose) Do(w http.ResponseWriter) apierror.APIError {
	token := database.Token{}
	refresh_token, err := token.New(p.User_id)
	if err != nil {
		return apierror.New(err, "Can't create token", "Internal Server Error", 500)
	}

	SetResponse(w, response_token_get{
		Token:         token.String,
		Refresh_token: refresh_token.String,
	}, http.StatusOK)
	return nil
}

func (p token_get_purpose) Name() string {
	return "token"
}

type response_token_get struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}
