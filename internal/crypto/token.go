package crypto

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
)

type TokenBody struct {
	Type          string `json:"type"`
	Id            uint64 `json:"id"`
	User_id       uint64 `json:"user_id"`
	Creation_date int64  `json:"creation_date"`
}

// return token in string format
func (body *TokenBody) Gen(salt []byte) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":          body.Type,
		"id":            body.Id,
		"user_id":       body.User_id,
		"creation_date": body.Creation_date,
	}).SignedString(salt)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (body *TokenBody) Parse(token_str string) error {
	rawbody, err := jwt.DecodeSegment(strings.Split(token_str, ".")[1])
	if err != nil {
		return err
	}
	err = json.Unmarshal(rawbody, &body)
	return err
}

func (body TokenBody) Check(token_str string, salt []byte) (bool, error) {
	token_obj, err := jwt.Parse(token_str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(salt), nil
	})
	if err != nil {
		return false, err
	}

	_, ok := token_obj.Claims.(jwt.MapClaims)
	return ok && token_obj.Valid, nil
}
