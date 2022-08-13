package database

import (
	"encoding/hex"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type TemporaryPassword struct {
	Cache    TemporaryPasswordCache
	Purpose  PurposeCache
	Selected bool
}

/*
Requirements:
	1) Temporary token id
*/
func (password *TemporaryPassword) Check(temporary_token string, temporary_password string) (bool, bool, error) {
	err := password.Cache.Select()
	if err != nil {
		return false, false, err
	}

	return crypto.CheckToken(temporary_token, password.Cache.Salt),
		(temporary_password == password.Cache.Password), nil
}

// token id must be setted
func (password *TemporaryPassword) New(login string) (string, error) {
	// set purpose in database
	err := password.Purpose.Insert()
	if err != nil {
		return "", err
	}

	// set temporary password params
	password.Cache.Purpose_id = password.Purpose.Id
	password.Cache.Password = settings.TemporaryPasswordSend(login)
	password.Cache.Salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	// set temporary password cache in database
	err = password.Cache.Insert()
	if err != nil {
		return "", err
	}

	// gen temporary token
	token, err := crypto.GenTemporaryToken(crypto.TemporaryTokenBody{
		Temporary_token_id: password.Cache.Id,
		Creation_date:      time.Now().UTC().UnixNano(),
		Login:              login}, password.Cache.Salt)
	return token, err
}

func (password *TemporaryPassword) Update(login string) (string, error) {
	// set temporary password params
	password.Cache.Password = settings.TemporaryPasswordSend(login)
	password.Cache.Salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	// set temporary password cache in database
	err := password.Cache.Update()
	if err != nil {
		return "", err
	}

	token, err := crypto.GenTemporaryToken(crypto.TemporaryTokenBody{
		Temporary_token_id: password.Cache.Id,
		Creation_date:      time.Now().UTC().UnixNano(),
		Login:              login}, password.Cache.Salt)

	return token, err
}

// how temporary password is implmented in database
type TemporaryPasswordCache struct {
	Id         uint64
	Purpose_id uint64
	Password   string
	Salt       []byte
}

// token id must be setted
func (cache *TemporaryPasswordCache) Select() error {
	var salt string
	err := GetDB().QueryRow("SELECT purpose_id_, password_, salt_ FROM purpostemporary_passwordses WHERE temporary_password_id_=$1;",
		cache.Id).Scan(&cache.Purpose_id, &cache.Password, &salt)
	if err != nil {
		return err
	}

	cache.Salt, err = hex.DecodeString(salt)
	if err != nil {
		return err
	}

	return nil
}

func (cache *TemporaryPasswordCache) Insert() error {
	err := GetDB().QueryRow("INSERT INTO temporary_passwords (purpose_id_, password_, salt_) VALUES ($1, $2, $3) RETURNING temporary_password_id_;",
		cache.Purpose_id, cache.Password, hex.EncodeToString(cache.Salt)).Scan(&cache.Id)
	return err
}

func (cache *TemporaryPasswordCache) Update() error {
	_, err := GetDB().Query("UPDATE temporary_passwords SET purpose_id_=$1, password_=$2, salt_=$3 WHERE temporary_password_id_=$4;",
		cache.Purpose_id, cache.Password, hex.EncodeToString(cache.Salt), cache.Id)
	return err
}

func (cache *TemporaryPasswordCache) Delete() error {
	_, err := GetDB().Query("DELETE FROM temporary_passwords WHERE temporary_password_id_==$1;", cache.Id)
	return err
}

type PurposeCache struct {
	Id      uint64
	Purpose string
	Data    []byte
}

// token id must be setted
func (cache *PurposeCache) Select() error {
	err := GetDB().QueryRow("SELECT purposes_, data_ FROM purposes WHERE purpose_id_=$1;",
		cache.Id).Scan(&cache.Purpose, &cache.Data)
	return err
}

func (cache *PurposeCache) Insert() error {
	err := GetDB().QueryRow("INSERT INTO purposes (purposes_, data_) VALUES ($1, $2) RETURNING purpose_id_;",
		cache.Purpose, string(cache.Data)).Scan(&cache.Id)
	return err
}

func (cache *PurposeCache) Delete() error {
	_, err := GetDB().Query("DELETE FROM purposes WHERE purpose_id_==$1;", cache.Id)
	return err
}
