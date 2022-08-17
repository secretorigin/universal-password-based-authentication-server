package database

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

const TEMPORARY_TOKEN_TYPE = "temporary"

type TemporaryToken struct {
	String string
	Uint64 uint64
}

// if you do not want to check temporary password just set it ""
func (token TemporaryToken) Check(password string, login *Login) (bool, error) {
	var body crypto.TemporaryTokenBody
	err := body.Parse(token.String)
	if err != nil {
		return false, err
	}
	if body.Type != TEMPORARY_TOKEN_TYPE {
		return false, errors.New("wrong token type")
	}
	login.String = body.Login

	var salt string
	var password_from_db string
	if password == "" {
		err = GetDB().QueryRow("SELECT salt_ FROM temporary_passwords WHERE temporary_password_id_=$1;",
			body.Id).Scan(&salt)
	} else {
		err = GetDB().QueryRow("SELECT salt_, password_ FROM temporary_passwords WHERE temporary_password_id_=$1;",
			body.Id).Scan(&salt, &password_from_db)
	}
	if err != nil {
		return false, err
	}

	salt_bytes, err := hex.DecodeString(salt)
	if err != nil {
		return false, err
	}

	ok, err := body.Check(token.String, salt_bytes)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("wrong token")
	}

	if password == "" {
		return ok, nil
	} else {
		return password == password_from_db, nil
	}
}

/*
	return temporary password
*/
func (token *TemporaryToken) New(login string, purpose string, data interface{}) error {
	// gen salts
	var salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)

	data_bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// insert in database and send temporary password
	err = GetDB().QueryRow("INSERT INTO temporary_passwords (purpose_, data_, password_, salt_) VALUES ($1, $2, $3, $4) RETURNING temporary_password_id_;",
		purpose, string(data_bytes), settings.TemporaryPasswordSend(login), hex.EncodeToString(salt)).Scan(&token.Uint64)
	if err != nil {
		return err
	}

	// gen token
	token_body := crypto.TemporaryTokenBody{
		Type:          TEMPORARY_TOKEN_TYPE,
		Id:            token.Uint64,
		Login:         login,
		Creation_date: time.Now().UnixMicro(),
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return err
	}

	return nil
}

func (token *TemporaryToken) Update(login Login) error {
	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.TemporaryTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return err
		}
		if body.Type != TEMPORARY_TOKEN_TYPE {
			return errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	// gen salts
	var salt = crypto.GenSalt(settings.TOKEN_SALT_SIZE)
	// insert salt in database and resend temporary password
	_, err := GetDB().Query("UPDATE temporary_passwords SET password_=$1, salt_=$2 WHERE temporary_password_id_=$3;",
		settings.TemporaryPasswordSend(login.String), hex.EncodeToString(salt), token.Uint64)
	if err != nil {
		return err
	}

	// gen token
	token_body := crypto.TemporaryTokenBody{
		Type:          TEMPORARY_TOKEN_TYPE,
		Id:            token.Uint64,
		Login:         login.String,
		Creation_date: time.Now().UnixMicro(),
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return err
	}

	return nil
}

func (token *TemporaryToken) Delete() error {
	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.TemporaryTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return err
		}
		if body.Type != TEMPORARY_TOKEN_TYPE {
			return errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	// insert salt in database and resend temporary password
	_, err := GetDB().Query("DELETE FROM temporary_passwords WHERE temporary_password_id_=$1;",
		token.Uint64)
	return err
}

type Purpose struct {
	Name string
	Data string
}

func (token *TemporaryToken) GetPurpose() (Purpose, error) {
	var purpose Purpose // will be returned

	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.TemporaryTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return Purpose{}, err
		}
		if body.Type != TEMPORARY_TOKEN_TYPE {
			return Purpose{}, errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	// insert salt in database and resend temporary password
	err := GetDB().QueryRow("SELECT purpose_, data_ FROM temporary_passwords WHERE temporary_password_id_=$1;",
		token.Uint64).Scan(&purpose.Name, &purpose.Data)
	return purpose, err
}
