package database

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

const (
	TOKEN_TYPE         = "token"
	REFRESH_TOKEN_TYPE = "refresh"
)

type Token struct {
	String string
	Uint64 uint64
}

type tokenCache struct {
	Id           uint64
	User_id      uint64
	Salt         []byte
	Refresh_salt []byte
}

/*
	token type must be: "token"/"refresh"
*/
func (token Token) Check(token_type string, user_id *uint64) (bool, error) {
	var body crypto.TokenBody
	err := body.Parse(token.String)
	if err != nil {
		return false, err
	}
	*user_id = body.User_id
	if body.Type != token_type {
		return false, errors.New("wrong token type")
	}
	token.Uint64 = body.Id

	var salt string
	if body.Type == "token" {
		err = GetDB().QueryRow("SELECT salt_ FROM tokens WHERE token_id_=$1;",
			token.Uint64).Scan(&salt)
	} else if body.Type == "refresh" {
		err = GetDB().QueryRow("SELECT refresh_salt_ FROM tokens WHERE token_id_=$1;",
			token.Uint64).Scan(&salt)
	} else {
		return false, errors.New("wrong type")
	}
	if err != nil {
		return false, err
	}

	salt_bytes, err := hex.DecodeString(salt)
	if err != nil {
		return false, err
	}

	return body.Check(token.String, salt_bytes)
}

/*
	return refresh token
*/
func (token *Token) New(user_id uint64) (Token, error) {
	var refresh_token Token // will be returned
	// gen salts
	var salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	var refresh_salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)

	// insert in database
	err := GetDB().QueryRow("INSERT INTO tokens (user_id_, salt_, refresh_salt_) VALUES ($1, $2, $3) RETURNING token_id_;",
		user_id, hex.EncodeToString(salt), hex.EncodeToString(refresh_salt)).Scan(&token.Uint64)
	refresh_token.Uint64 = token.Uint64
	if err != nil {
		return Token{String: ""}, err
	}

	// gen token
	token_body := crypto.TokenBody{
		Type:          TOKEN_TYPE,
		Id:            token.Uint64,
		User_id:       user_id,
		Creation_date: time.Now().UnixMicro(),
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return Token{String: ""}, err
	}
	// gen refresh token
	refresh_token_body := crypto.TokenBody{
		Type:          REFRESH_TOKEN_TYPE,
		Id:            refresh_token.Uint64,
		User_id:       user_id,
		Creation_date: time.Now().UnixMicro(),
	}
	refresh_token.String, err = refresh_token_body.Gen(refresh_salt)
	if err != nil {
		return Token{String: ""}, err
	}

	return refresh_token, nil
}

/*
	update passed by reference token
	get new salt and refresh_salt
	return refresh token
*/
func (token *Token) Update(user_id *uint64) (Token, error) {
	var refresh_token Token // will be returned

	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.TokenBody
		err := body.Parse(token.String)
		if err != nil {
			return Token{String: ""}, err
		}
		if body.Type != REFRESH_TOKEN_TYPE {
			return Token{String: ""}, errors.New("wrong token type")
		}
		token.Uint64 = body.Id
		refresh_token.Uint64 = body.Id
		*user_id = body.User_id
	}

	var salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	var refresh_salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)

	// insert in database
	_, err := GetDB().Query("UPDATE tokens SET salt_=$1, refresh_salt_=$2 WHERE token_id_=$3;",
		hex.EncodeToString(salt), hex.EncodeToString(refresh_salt), token.Uint64)
	if err != nil {
		return Token{String: ""}, err
	}

	// gen token
	token_body := crypto.TokenBody{
		Type:          TOKEN_TYPE,
		Id:            token.Uint64,
		User_id:       *user_id,
		Creation_date: time.Now().UnixMicro(),
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return Token{String: ""}, err
	}
	// gen refresh token
	refresh_token_body := crypto.TokenBody{
		Type:          REFRESH_TOKEN_TYPE,
		Id:            refresh_token.Uint64,
		User_id:       *user_id,
		Creation_date: time.Now().UnixMicro(),
	}
	refresh_token.String, err = refresh_token_body.Gen(refresh_salt)
	if err != nil {
		return Token{String: ""}, err
	}

	return refresh_token, nil
}

func (token Token) Delete(refresh_token_str string) error {
	if token.Uint64 == 0 {
		var body crypto.TokenBody
		err := body.Parse(refresh_token_str)
		if err != nil {
			return err
		}
		if body.Type != REFRESH_TOKEN_TYPE {
			return errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	_, err := GetDB().Query("DELETE FROM tokens WHERE token_id_=$1;", token.Uint64)
	if err != nil {
		return err
	}

	return nil
}
