package field

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenCache struct {
	Token_id      uint64  `json:"token_id"`
	User_id       uint64  `json:"user_id"`
	Creation_date float64 `json:"creation_date"`
}

/* . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
	generate new token
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . */
func GenToken(user_id, token_id uint64) (string, string) {
	salt := Random(uint(TOKEN_SALT_LENGTH), []rune(TOKEN_SALT_CHARS))

	token_str, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":       user_id,
		"token_id":      token_id,
		"creation_date": float64(time.Now().UnixMilli()) / float64(1000),
	}).SignedString([]byte(salt))

	if err != nil {
		log.Println(err.Error())
		return "", ""
	}

	return token_str, salt
}

func GenToken(user_id, token_id uint64) (string, string) {
	salt := Random(uint(TOKEN_SALT_LENGTH), []rune(TOKEN_SALT_CHARS))

	token_str, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":       user_id,
		"token_id":      token_id,
		"creation_date": float64(time.Now().UnixMilli()) / float64(1000),
	}).SignedString([]byte(salt))

	if err != nil {
		log.Println(err.Error())
		return "", ""
	}

	return token_str, salt
}

/* . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
	check token
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . */
// salt_name: "salt" / "refresh_salt"
func CheckToken(db *sql.DB, token string, salt_name string) (TokenCache, errs.ErrorCode) {
	var inside TokenCache

	// get token's inside
	b, err := jwt.DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		return inside, errs.Token(errs.Wrong_Format())
	}
	err = json.Unmarshal(b, &inside)
	if err != nil {
		return inside, errs.Token(errs.Wrong_Format())
	}

	// get salt
	var salt string
	var date float64
	err = db.QueryRow(fmt.Sprintf("SELECT "+salt_name+", creation_date FROM tokens WHERE id = %d;",
		inside.Token_id)).Scan(&salt, &date)
	if err == sql.ErrNoRows {
		return inside, errs.Token(errs.Not_Exist())
	} else if err != sql.ErrNoRows && err != nil {
		logger.Error(err.Error())
		return inside, errs.Server()
	}

	if salt_name == "salt" {
		// check token livetime
		if Timelimit_passed(date, fmt.Sprintf("%dm", TOKEN_LIFETIME_MINUTES)) {
			return inside, errs.Token(errs.Use(errs.Time_Limit(errs.Passed())))
		}
	} else {
		// check refresh token livetime
		if Timelimit_passed(date, fmt.Sprintf("%dh", REFRESH_TOKEN_LIFETIME_HOURS)) {
			return inside, errs.Token(errs.Use(errs.Time_Limit(errs.Passed())))
		}
	}

	// check token
	token_obj, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(salt), nil
	})

	if _, ok := token_obj.Claims.(jwt.MapClaims); ok && token_obj.Valid {
		return inside, errs.Ok()
	} else {
		return inside, errs.Token(errs.Wrong())
	}
}
