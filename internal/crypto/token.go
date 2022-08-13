package crypto

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
)

type TokenBody struct {
	Token_id      uint64 `json:"token_id"`
	User_id       uint64 `json:"user_id"`
	Creation_date int64  `json:"creation_date"`
}

func GenToken(body TokenBody, salt []byte) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"token_id":      body.Token_id,
		"user_id":       body.User_id,
		"creation_date": body.Creation_date,
	}).SignedString(salt)
	if err != nil {
		return "", err
	}

	return token, nil
}

func ParseToken(token_str string) (body TokenBody, err error) {
	rawbody, err := jwt.DecodeSegment(strings.Split(token_str, ".")[1])
	if err != nil {
		return body, err
	}
	err = json.Unmarshal(rawbody, &body)
	return body, err
}

func CheckToken(token_str string, salt []byte) bool {
	if token_str == "" {
		return false
	}

	token_obj, _ := jwt.Parse(token_str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(salt), nil
	})

	_, ok := token_obj.Claims.(jwt.MapClaims)
	return ok && token_obj.Valid
}
