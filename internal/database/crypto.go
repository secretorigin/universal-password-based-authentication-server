package database

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	_ "github.com/lib/pq"
	"github.com/p2034/universal-password-based-authentication-server/internal/field"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func CheckAccessPart(refresh_token string, password string) (field.TokenBody, bool) {
	// check password and token
	token_body := field.ParseTokenBody(refresh_token)
	if !CheckToken(refresh_token, token_body.Token_id, false) {
		if settings.DebugMode {
			log.Println("Error: Wrong token.")
		}
		return token_body, false
	}
	if !CheckPassword(token_body.User_id, password) {
		if settings.DebugMode {
			log.Println("Error: Wrong password.")
		}
		return token_body, false
	}

	return token_body, true
}

func CheckTemporaryToken(temporary_token string, temporary_token_id uint64) bool {
	var salt string
	err := GetDB().QueryRow("SELECT salt_ FROM temporary_passwords WHERE temporary_password_id_=$1;", temporary_token_id).Scan(&salt)
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
	return field.CheckToken(salt_bytes, temporary_token)
}

func CheckTemporaryPassword(temporary_password string, temporary_password_id uint64) bool {
	var password_from_db string
	err := GetDB().QueryRow("SELECT password_ FROM temporary_passwords WHERE temporary_password_id_=$1;", temporary_password_id).Scan(&password_from_db)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Println(err.Error())
		}
		return false
	}

	return (temporary_password == password_from_db)
}

// returning temporary token
func GenTemporaryPassword(temporary_password string, purpose string, data interface{}) string {
	var temporary_password_id uint64

	salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	data_bytes, err := json.Marshal(data)
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	err = GetDB().QueryRow("INSERT INTO temporary_passwords (password_, salt_, purpose_, data_) VALUES ($1, $2, $3, $4) RETURNING temporary_password_id_;",
		temporary_password, hex.EncodeToString(salt), purpose, string(data_bytes)).Scan(&temporary_password_id)
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	token := field.GenTemporaryToken(salt, field.TemporaryTokenBody{Temporary_token_id: temporary_password_id, Creation_date: time.Now().UTC().UnixNano()})

	return token
}

// token_type = true => it's token, if token_type = false it's refresh_token
func CheckToken(token string, token_id uint64, token_type bool) bool {
	var salt string
	var query string
	if token_type {
		query = "salt_"
	} else {
		query = "refresh_salt_"
	}
	err := GetDB().QueryRow("SELECT "+query+" FROM tokens WHERE token_id_=$1;", token_id).Scan(&salt)
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
	return field.CheckToken(salt_bytes, token)
}

// return token and refresh_token
func UpdateToken(refresh_token string, user_id, token_id uint64) (string, string) {
	// check token
	var refresh_salt string
	err := GetDB().QueryRow("SELECT refresh_salt_ FROM tokens WHERE token_id_=$1;", token_id).Scan(&refresh_salt)
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
	_, err = GetDB().Query("UPDATE tokens SET salt_=$1, refresh_salt_=$2 WHERE token_id_=$3;",
		hex.EncodeToString(new_salt), hex.EncodeToString(new_refresh_salt), token_id)
	if err != nil {
		log.Println(err.Error())
		return "", ""
	}

	new_token := field.GenToken(new_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})
	new_refresh_token := field.GenToken(new_refresh_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})

	return new_token, new_refresh_token
}

func GenToken(user_id uint64) (string, string) {
	var token_id uint64

	salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	refresh_salt := field.GenSalt(settings.TOKEN_SALT_SIZE)
	err := GetDB().QueryRow("INSERT INTO tokens (user_id_, salt_, refresh_salt_) VALUES ($1, $2, $3) RETURNING token_id_;",
		user_id, hex.EncodeToString(salt), hex.EncodeToString(refresh_salt)).Scan(&token_id)
	if err != nil {
		log.Println(err.Error())
		return "", ""
	}

	token := field.GenToken(salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})
	refresh_token := field.GenToken(refresh_salt, field.TokenBody{Token_id: token_id, User_id: user_id, Creation_date: time.Now().UTC().UnixNano()})

	return token, refresh_token
}

func CheckPassword(id uint64, password string) bool {
	var hash_from_db string
	var iterations int

	err := GetDB().QueryRow("SELECT password_hash_, password_iterations_ FROM users WHERE user_id_=$1;", id).Scan(&hash_from_db, &iterations)
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
