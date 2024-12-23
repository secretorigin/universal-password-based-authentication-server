package database

import (
	"encoding/hex"
)

type User struct {
	Uint64 uint64
	String string
}

type userCache struct {
	PasswordCache
	Id    uint64
	TwoFA bool
	Login string
}

func (user *User) New(pcache PasswordCache) error {
	cache := userCache{PasswordCache: pcache, Login: user.String}
	err := GetDB().QueryRow(
		"INSERT INTO users (login_, password_hash_, password_iterations_) VALUES "+
			"($1, $2, $3) RETURNING user_id_;",
		cache.Login, hex.EncodeToString(cache.Hash), cache.Iterations,
	).Scan(&user.Uint64)
	return err
}

func (user User) GetTwoFA() (twofa bool, err error) {
	err = GetDB().QueryRow("SELECT twofa_ FROM users WHERE user_id_=$1;",
		user.Uint64).Scan(&twofa)
	if err != nil {
		return twofa, err
	}

	return twofa, err
}

func (user User) TwoFA() error {
	_, err := GetDB().Query("UPDATE users SET twofa_ = NOT twofa_ WHERE user_id_ = $1;", user.Uint64)
	return err
}

func (user *User) GetId() error {
	err := GetDB().QueryRow("SELECT user_id_ FROM users WHERE login_=$1;",
		user.String).Scan(&user.Uint64)
	return err
}

func (user *User) GetLogin() error {
	err := GetDB().QueryRow("SELECT login_ FROM users WHERE user_id_=$1;",
		user.Uint64).Scan(&user.String)
	return err
}

func (user User) LogoutEverywhere() error {
	_, err := GetDB().Query("DELETE FROM tokens WHERE user_id_=$1;", user.Uint64)
	return err
}

func (user User) Delete() error {
	_, err := GetDB().Query("DELETE FROM users WHERE user_id_=$1;", user.Uint64)
	return err
}
