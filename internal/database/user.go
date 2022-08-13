package database

import (
	"encoding/hex"
	"math/rand"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type User struct {
	Cache UserCache
}

/*
User id or login must be setted
*/
// user id or login must be setted
func (user *User) Check(password string) (bool, error) {
	err := user.Cache.Select()
	if err != nil {
		return false, err
	}
	if err != nil {
		return false, err
	}

	return crypto.CheckPassword(user.Cache.Password.Hash, []byte(password), int(user.Cache.Password.Iterations)), nil
}

/*
Requirements:
	1) Login
*/
func (user *User) New(password string) error {
	user.Cache.Password.Iterations = uint32(rand.Int31()%1000) + settings.PASSWORD_MIN_ITERATIONS_COUNT
	user.Cache.Password.Hash = crypto.HashPassword(
		crypto.GenSalt(settings.PASSWORD_SALT_SIZE),
		int(user.Cache.Password.Iterations),
		[]byte(password))

	err := user.Cache.Insert()
	return err
}

/*
Requirements:
	1) User id
*/
func (user *User) ChangePassword(new_password string) error {
	user.Cache.Password.Iterations = uint32(rand.Int31()%1000) + settings.PASSWORD_MIN_ITERATIONS_COUNT
	user.Cache.Password.Hash = crypto.HashPassword(
		crypto.GenSalt(settings.PASSWORD_SALT_SIZE),
		int(user.Cache.Password.Iterations),
		[]byte(new_password))

	_, err := GetDB().Query("UPDATE users SET password_hash_=$1, password_iterations_=$2 WHERE user_id_=$3;",
		hex.EncodeToString(user.Cache.Password.Hash), user.Cache.Password.Iterations, user.Cache.Id)
	return err
}

/*
Requirements:
	1) User id
*/
func (user *User) ChangeLogin(new_login string) error {
	_, err := GetDB().Query("UPDATE users SET login_=$1 WHERE user_id_=$2;",
		new_login, user.Cache.Id)
	return err
}

/*
Requirements:
	1) User id
*/
func (user *User) LogoutEverywhere(except uint64) error {
	_, err := GetDB().Query("DELETE FROM tokens WHERE user_id_=$1 AND NOT token_id_=$2;",
		user.Cache.Id, except)
	return err
}

// how user is implmented in database
type UserCache struct {
	Id       uint64
	Login    string
	Password PasswordCache
}

type PasswordCache struct {
	Hash       []byte
	Iterations uint32
}

// where is some database calls for гыук control

// field is a field which will be used as selector
func (cache *UserCache) Select() error {
	var hash string
	var err error

	if cache.Login != "" {
		err = GetDB().QueryRow("SELECT user_id_, password_hash_, password_iterations_ FROM users WHERE login_=$1;",
			cache.Login).Scan(&cache.Id, &hash, &cache.Password.Iterations)
	} else {
		err = GetDB().QueryRow("SELECT login_, password_hash_, password_iterations_ FROM users WHERE user_id_=$1;",
			cache.Id).Scan(&cache.Login, &hash, &cache.Password.Iterations)
	}
	if err != nil {
		return err
	}

	cache.Password.Hash, err = hex.DecodeString(hash)
	return err
}

func (cache *UserCache) Insert() error {
	err := GetDB().QueryRow(
		"INSERT INTO users (login_, password_hash_, password_iterations_) VALUES "+
			"($1, $2, $3) RETURNING user_id;",
		cache.Login, hex.EncodeToString(cache.Password.Hash), cache.Password.Iterations,
	).Scan(&cache.Id)
	return err
}

func (cache *UserCache) Update() error {
	_, err := GetDB().Query("UPDATE users SET login_=$1, password_hash_=$2, password_iterations_=$3 WHERE user_id_=$4;",
		cache.Login, hex.EncodeToString(cache.Password.Hash), cache.Password.Iterations, cache.Id)
	return err
}

func (cache *UserCache) Delete() error {
	_, err := GetDB().Query("DELETE FROM users WHERE user_id_=$1;", cache.Id)
	// if it will not be completed, it's not very important for user
	_, _ = GetDB().Query("DELETE FROM tokens WHERE user_id_=$1;", cache.Id)
	return err
}
