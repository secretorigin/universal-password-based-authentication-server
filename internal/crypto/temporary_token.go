package crypto

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt"
)

/*
	This token is used for validation action /confirm with temporary password
*/

// token for temporary password
type TemporaryTokenBody struct {
	Temporary_token_id uint64 `json:"temporary_token_id"`
	Creation_date      int64  `json:"creation_date"`
	Login              string `json:"login"`
}

func GenTemporaryToken(body TemporaryTokenBody, salt []byte) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"temporary_token_id": body.Temporary_token_id,
		"creation_date":      body.Creation_date,
		"login":              body.Login,
	}).SignedString(salt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func ParseTemporaryToken(token string) (TemporaryTokenBody, error) {
	var body TemporaryTokenBody
	rawbody, err := jwt.DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		return body, err
	}
	err = json.Unmarshal(rawbody, body)
	return body, err
}
