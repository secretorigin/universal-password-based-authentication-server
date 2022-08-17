package database

import (
	"encoding/hex"
)

type User struct {
	Uint64 uint64
	String string
}

type userCache struct {
	passwordCache
	Id    uint64
	Login string
}

func (user User) New(password Password) error {
	cache := userCache{passwordCache: password.Gen(), Login: user.String}
	err := GetDB().QueryRow(
		"INSERT INTO users (login_, password_hash_, password_iterations_) VALUES "+
			"($1, $2, $3) RETURNING user_id;",
		cache.Login, hex.EncodeToString(cache.Hash), cache.Iterations,
	).Scan(&user.Uint64)
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
