package database

import (
	"encoding/hex"
	"math/rand"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type Password struct {
	String string
}

type PasswordCache struct {
	Hash       []byte
	Iterations uint32
}

func (password Password) Check(user User) (bool, error) {
	var cache PasswordCache
	var hash string
	err := GetDB().QueryRow("SELECT password_hash_, password_iterations_ FROM users WHERE user_id_=$1;",
		user.Uint64).Scan(&hash, &cache.Iterations)
	if err != nil {
		return false, err
	}

	cache.Hash, err = hex.DecodeString(hash)
	if err != nil {
		return false, err
	}

	return crypto.CheckPassword(cache.Hash, []byte(password.String), int(cache.Iterations)), nil
}

func (password Password) Change(user_id uint64) error {
	cache := password.Gen()

	_, err := GetDB().Query("UPDATE users SET password_hash_=$1, password_iterations_=$2 WHERE user_id_=$3;",
		hex.EncodeToString(cache.Hash), cache.Iterations, user_id)

	return err
}

func (password Password) Gen() PasswordCache {
	var cache PasswordCache

	cache.Iterations = uint32(rand.Int31()%1000) + settings.Conf.Security.Password.MinIterations
	cache.Hash = crypto.HashPassword(
		crypto.GenSalt(int(settings.Conf.Security.Password.SaltLength)),
		int(cache.Iterations),
		[]byte(password.String))

	return cache
}
