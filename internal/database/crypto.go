package database

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	Token
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
// token_type = true => it's token, if token_type = false it's refresh_token
func CheckToken(db *sql.DB, token string, token_id int, token_type bool) bool {
	var salt string
	var query string
	if token_type {
		query = "salt_"
	} else {
		query = "refresh_salt_"
	}
	err := db.QueryRow("SELECT "+query+" FROM tokens WHERE token_id_=$1;", token_id).Scan(&salt)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Println(err.Error())
		}
		return false
	}
	salt_bytes, err := hex.DecodeString(salt)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	// DEBUG
	fmt.Println(salt_bytes)
	fmt.Println(token_id)
	return field.CheckToken(salt_bytes, token)
}

func UpdateToken(db *sql.DB, refresh_token string, user_id, token_id uint64) (string, string) {
	// check token
	var refresh_salt string
	err := db.QueryRow("SELECT refresh_salt_ FROM tokens WHERE token_id_=$1;", token_id).Scan(&refresh_salt)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Println(err.Error())
		}
		return "", ""
	}

	refresh_salt_bytes, err := hex.DecodeString(refresh_salt)
	if err != nil {
		log.Println(err.Error())
		return "", ""
	}
	if !field.CheckToken(refresh_salt_bytes, refresh_token) {
		return "", ""
	}

	// gen new tokens
	new_salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	new_refresh_salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	_, err = db.Query("UPDATE tokens SET salt_=$1, refresh_salt_=$2 WHERE token_id_=$3;",
		hex.EncodeToString(new_salt), hex.EncodeToString(new_refresh_salt), token_id)
	if err != nil {
		log.Println(err.Error())
		return "", ""
	}

	new_token := field.GenToken(new_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})
	new_refresh_token := field.GenToken(new_refresh_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})

	return string(new_token), string(new_refresh_token)
}

func GenToken(db *sql.DB, user_id uint64) (string, string) {
	var token_id uint64

	salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	refresh_salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	err := db.QueryRow("INSERT INTO tokens (salt_, refresh_salt_) VALUES ($1, $2) RETURNING token_id_;",
		hex.EncodeToString(salt), hex.EncodeToString(refresh_salt)).Scan(&token_id)
	if err != nil {
		log.Println(err.Error())
		return "", ""
	}
	// DEBUG
	fmt.Println(salt)
	fmt.Println(refresh_salt)
	fmt.Println(token_id)

	token := field.GenToken(salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})
	refresh_token := field.GenToken(refresh_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})

	return string(token), string(refresh_token)
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	Password
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
func CheckPasswordWithUserId(db *sql.DB, id uint64, password string) bool {
	var hash_from_db string
	var iterations int

	err := db.QueryRow("SELECT password_hash_, password_iterations_ FROM users WHERE user_id_=$1;", id).Scan(&hash_from_db, &iterations)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Println(err.Error())
		}
		return false
	}

	bytes, err := hex.DecodeString(hash_from_db)
	if err != nil {
		log.Println(err.Error())
		return false
	}

	return field.CheckPassword(bytes, []byte(password), iterations)
}
