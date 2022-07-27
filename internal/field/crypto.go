package field

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
	"golang.org/x/crypto/pbkdf2"
)

func GenSalt(size int) []byte {
	salt := make([]byte, size)
	rand.Read(salt)
	return salt
}

// token for temporary password
type TemporaryTokenBody struct {
	Temporary_token_id uint64 `json:"temporary_token_id"`
	Creation_date      int64  `json:"creation_date"`
}

func GenTemporaryToken(salt []byte, body TemporaryTokenBody) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"temporary_token_id": body.Temporary_token_id,
		"creation_date":      body.Creation_date,
	}).SignedString(salt)
	if err != nil {
		log.Println(err.Error())
	}

	return token
}

func ParseTemporaryTokenBody(token string) TemporaryTokenBody {
	var body TemporaryTokenBody

	rawbody, err := jwt.DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		log.Println(err.Error())
	}
	err = json.Unmarshal(rawbody, &body)
	if err != nil {
		log.Println(err.Error())
	}

	return body
}

type TokenBody struct {
	Token_id      uint64 `json:"token_id"`
	User_id       uint64 `json:"user_id"`
	Creation_date int64  `json:"creation_date"`
}

func GenToken(salt []byte, body TokenBody) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"token_id":      body.Token_id,
		"user_id":       body.User_id,
		"creation_date": body.Creation_date,
	}).SignedString(salt)
	if err != nil {
		log.Println(err.Error())
	}

	return token
}

func ParseTokenBody(token string) TokenBody {
	var body TokenBody

	rawbody, err := jwt.DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		log.Println(err.Error())
	}
	err = json.Unmarshal(rawbody, &body)
	if err != nil {
		log.Println(err.Error())
	}

	return body
}

// for all tokens
func CheckToken(salt []byte, token string) bool {
	token_obj, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(salt), nil
	})

	_, ok := token_obj.Claims.(jwt.MapClaims)
	return ok && token_obj.Valid
}

func HashPassword(salt []byte, password []byte, iterations int) []byte {
	passwordHash := pbkdf2.Key(password, salt, iterations, settings.PASSWORD_HASH_LENGTH, sha256.New)
	return append(salt, passwordHash...)
}

func CheckPassword(passwordHash []byte, password []byte, iterations int) bool {
	passwordHashSave := make([]byte, len(passwordHash)) // because it changes
	copy(passwordHashSave, passwordHash)
	userPassHash := HashPassword(passwordHash[0:settings.PASSWORD_SALT_SIZE], password, iterations)
	return bytes.Equal(userPassHash, passwordHashSave)
}
