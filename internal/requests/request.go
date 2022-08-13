package requests

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/p2034/universal-password-based-authentication-server/internal/apierror"
	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
)

type Request interface {
	Init(*http.Request) apierror.APIError       // check request method
	Validate() apierror.APIError                // check fields in request
	Do(w http.ResponseWriter) apierror.APIError // do magic
}

func Handler[RequestType Request]() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var request RequestType
		if err := request.Init(r); err != nil {
			ErrorHandler(w, err)
			return
		}

		// get body
		err := json.NewDecoder(r.Body).Decode(request)
		if err != nil {
			ErrorHandler(w, apierror.BodyFormat)
			return
		}
		defer r.Body.Close()

		if err := request.Validate(); err != nil {
			ErrorHandler(w, err)
			return
		}

		if err := request.Do(w); err != nil {
			ErrorHandler(w, err)
			return
		}
	}
}

type access_part struct {
	Refresh_token string `json:"refresh_token"`
	Password      string `json:"password"`
}

func CheckAccessPart(ap access_part, token *database.Token, user *database.User) error {
	// parse token
	token_body, err := crypto.ParseToken(ap.Refresh_token)
	if err != nil {
		return err
	}

	// check token
	*token = database.Token{
		Cache: database.TokenCache{
			Id:      token_body.Token_id,
			User_id: token_body.User_id}}
	_, ok, err := token.Check("", ap.Refresh_token)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong token")
	}
	// check password
	*user = database.User{
		Cache: database.UserCache{
			Id:    token_body.User_id,
			Login: ""}}
	ok, err = user.Check(ap.Password)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong password")
	}

	return nil
}
