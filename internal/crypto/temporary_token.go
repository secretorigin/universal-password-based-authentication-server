package crypto

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
)

/*
	This token is used for validation action /confirm with temporary password
*/

// token for temporary password
type TemporaryTokenBody struct {
	Type          string `json:"type"`
	Id            uint64 `json:"id"`
	Login         string `json:"login"`
	Creation_date int64  `json:"creation_date"`
}

func (body *TemporaryTokenBody) Gen(salt []byte) (string, error) {
	body.Type = "temporary"
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":          body.Type,
		"id":            body.Id,
		"login":         body.Login,
		"creation_date": body.Creation_date,
	}).SignedString(salt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (body *TemporaryTokenBody) Parse(token string) error {
	rawbody, err := jwt.DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		return err
	}
	err = json.Unmarshal(rawbody, body)
	return err
}

func (body TemporaryTokenBody) Check(token_str string, salt []byte) (bool, error) {
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
