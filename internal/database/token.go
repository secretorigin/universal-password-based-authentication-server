package database

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Token struct {
	Cache TokenCache
}

/*
Get token from database and check it, first bool is

Requirements:
	1) Token id
*/
func (token *Token) Check(token_str string, refresh_token_str string) (bool, bool, error) {
	// get data from db
	user_id := token.Cache.User_id
	err := token.Cache.Select()
	if err != nil {
		return false, false, err
	}
	if token.Cache.User_id != user_id {
		return false, false, errors.New("wrong user id")
	}

	return crypto.CheckToken(token_str, token.Cache.Salt),
		crypto.CheckToken(token_str, token.Cache.Refresh_salt), nil
}

/*
Requirements:
	1) User id
*/
func (token *Token) New() (TokenPair, error) {
	tokens := TokenPair{"", ""}

	// gen token params
	token.Cache.Gen()

	// save params in db
	err := token.Cache.Insert()
	if err != nil {
		return tokens, err
	}

	// gen new pair
	tokens.Gen(token.Cache)
	return tokens, nil
}

/*
Requirements:
	1) Token id
*/
// token must be checked
func (token *Token) UpdateToken() (TokenPair, error) {
	tokens := TokenPair{"", ""}

	// gen new token params
	token.Cache.Gen()

	// update in db
	err := token.Cache.Update()
	if err != nil {
		return TokenPair{"", ""}, err
	}

	// gen new token pair
	tokens.Gen(token.Cache)
	return tokens, nil
}

// just a pair of refresh token and token

type TokenPair struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func (tokens *TokenPair) Gen(cache TokenCache) (err error) {
	tokens.Token, err = crypto.GenToken(
		crypto.TokenBody{
			Token_id:      cache.Id,
			User_id:       cache.User_id,
			Creation_date: time.Now().UTC().UnixNano()},
		cache.Salt)
	if err != nil {
		return err
	}
	tokens.RefreshToken, err = crypto.GenToken(
		crypto.TokenBody{
			Token_id:      cache.Id,
			User_id:       cache.User_id,
			Creation_date: time.Now().UTC().UnixNano()},
		cache.Refresh_salt)
	if err != nil {
		return err
	}

	return nil
}

// how token is implmented in database
type TokenCache struct {
	Id           uint64
	User_id      uint64
	Salt         []byte
	Refresh_salt []byte
}

func (cache *TokenCache) Gen() {
	cache.Salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	cache.Refresh_salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
}

// some database core logic functions

// token id must be setted
func (cache *TokenCache) Select() error {
	var salt string
	var refresh_salt string
	err := GetDB().QueryRow("SELECT user_id_, salt_, refresh_salt_ FROM tokens WHERE token_id_=$1;",
		cache.Id).Scan(&cache.User_id, &salt, &refresh_salt)
	if err != nil {
		return err
	}

	// decode salts
	cache.Salt, err = hex.DecodeString(salt)
	if err != nil {
		return err
	}
	cache.Salt, err = hex.DecodeString(refresh_salt)
	if err != nil {
		return err
	}

	return nil
}

func (cache *TokenCache) Insert() error {
	err := GetDB().QueryRow("INSERT INTO tokens (user_id_, salt_, refresh_salt_) VALUES ($1, $2, $3) RETURNING token_id_;",
		cache.User_id, hex.EncodeToString(cache.Salt), hex.EncodeToString(cache.Refresh_salt)).Scan(&cache.Id)
	return err
}

func (cache *TokenCache) Update() error {
	_, err := GetDB().Query("UPDATE tokens SET salt_=$1, refresh_salt_=$2 WHERE token_id_=$3;",
		hex.EncodeToString(cache.Salt), hex.EncodeToString(cache.Refresh_salt), cache.Id)
	return err
}

// id must be in token cache
func (cache *TokenCache) Delete() error {
	_, err := GetDB().Query("DELETE FROM tokens WHERE token_id_==$1;", cache.Id)
	return err
}
