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
	Login      string `json:"login"`
	Password   string `json:"password"`
	InviteCode string `json:"invite-code"`
}

func (request *request_user_create) Validate() apierror.APIError {
	if !(regexp.MustCompile(settings.Conf.Regex.Login).MatchString(request.Login) &&
		regexp.MustCompile(settings.Conf.Regex.Password).MatchString(request.Password)) {
		return apierror.FieldFormat
	}

	if settings.Conf.Security.InviteCode &&
		!regexp.MustCompile(settings.Conf.Regex.InviteCode).MatchString(request.InviteCode) {
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

	invite_code := database.InviteCode{Id: 0, Code: body.InviteCode}
	if settings.Conf.Security.InviteCode {
		invite_code.Code = body.InviteCode
		err := invite_code.Use()
		if err != nil {
			ErrorHandler(w, apierror.New(err, "invite code does not exist or already used", "Bad Request", 400))
			return
		}
	}

	password := database.Password{String: body.Password}
	cache := password.Gen()
	purpose := user_create_purpose{
		Login:      body.Login,
		Hash:       hex.EncodeToString(cache.Hash),
		Iterations: cache.Iterations}
	process2FAVariablePurpose(w, purpose, body.Login, settings.Conf.Verification.UserCreate)
}

// purpose when 2FA is activated

type user_create_purpose struct {
	InviteCodeId uint64 `json:"invite-code-id"`
	Login        string `json:"login"`
	Hash         string `json:"hash"`
	Iterations   uint32 `json:"iterations"`
}

func (p user_create_purpose) Do(w http.ResponseWriter) apierror.APIError {
	if !database.CheckLoginUnique(p.Login) {
		return apierror.LoginAlreadyExist
	}

	user := database.User{String: p.Login}
	hash, err := hex.DecodeString(p.Hash)
	if err != nil {
		return apierror.New(err, "wring hash format", "Internal Server Error", 500)
	}
	err = user.New(database.PasswordCache{Hash: hash, Iterations: p.Iterations})
	if err != nil {
		return apierror.New(err, "user creation", "Internal Server Error", 500)
	}

	SetResponse(w, response_user_create{User_id: user.Uint64}, http.StatusOK)
	return nil
}

func (p user_create_purpose) Name() string {
	return "create"
}

func (p user_create_purpose) Encode() []byte {
	body, _ := json.Marshal(p)
	return body
}

type response_user_create struct {
	User_id uint64 `json:"user_id"`
}
