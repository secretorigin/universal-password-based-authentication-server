package crypto

import (
	"bytes"
	"crypto/sha256"

	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
	"golang.org/x/crypto/pbkdf2"
)

func HashPassword(salt []byte, iterations int, password []byte) []byte {
	hash := pbkdf2.Key(password, salt, iterations, int(settings.Conf.Security.Password.HashLength), sha256.New)
	return append(salt, hash...)
}

func CheckPassword(passwordHash []byte, password []byte, iterations int) bool {
	passwordHashReference := make([]byte, len(passwordHash)) // because it changes
	copy(passwordHashReference, passwordHash)
	passwordHashChecked := HashPassword(passwordHash[0:settings.Conf.Security.Password.SaltLength], iterations, password)
	return bytes.Equal(passwordHashChecked, passwordHashReference)
}
