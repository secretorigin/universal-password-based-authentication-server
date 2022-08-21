package requests

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type request_user_create struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (request *request_user_create) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.LoginRegex).MatchString(request.Login) &&
		regexp.MustCompile(settings.PasswordRegex).MatchString(request.Password)) {
		return apierror.FieldFormat
	}

	if !database.CheckLoginUnique(request.Login) {
		return apierror.LoginAlreadyExist
	}

	return nil
}

func User_create(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/user/create" || r.Method != "POST" {
		ErrorHandler(w, apierror.NotFound)
		return
	}

	var body request_user_create
	apierr := parseRequestBody(r, &body)
	if apierr != nil {
		ErrorHandler(w, apierr)
		return
	}

	// process

	password := database.Password{String: body.Password}
	cache := password.Gen()
	purpose := user_create_purpose{
		Login:      body.Login,
		Hash:       hex.EncodeToString(cache.Hash),
		Iterations: cache.Iterations}
	process2FAVariablePurpose(w, purpose, body.Login, settings.UserCreate2FA)
}

// purpose when 2FA is activated

type user_create_purpose struct {
	Login      string `json:"login"`
	Hash       string `json:"hash"`
	Iterations uint32 `json:"iterations"`
}

func (p user_create_purpose) Do(w http.ResponseWriter) apierror.APIError {
	user := database.User{String: p.Login}
	hash, err := hex.DecodeString(p.Hash)
	if err != nil {
		return apierror.New(err, "wring hash format", "Internal Server Error", 500)
	}
	err = user.New(database.PasswordCache{Hash: hash, Iterations: p.Iterations})
	if err != nil {
		return apierror.New(err, "user creation", "Internal Server Error", 500)
	}

	SetResponse(w, nil, http.StatusOK)
	return nil
}

func (p user_create_purpose) Name() string {
	return "create"
}

func (p user_create_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}
