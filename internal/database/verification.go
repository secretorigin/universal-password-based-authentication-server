package database

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/p2034/universal-password-based-authentication-server/internal/crypto"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

type VerificationToken struct {
	String        string
	Uint64        uint64
	Creation_date int64
	Resended      uint16
}

// if you do not want to check verification code just set it ""
func (token *VerificationToken) Check(password string, login *Login) (bool, error) {
	var body crypto.VerificationTokenBody
	err := body.Parse(token.String)
	if err != nil {
		return false, err
	}
	if body.Type != crypto.VERIFICATION_TOKEN_TYPE {
		return false, errors.New("wrong token type")
	}
	login.String = body.Login
	token.Creation_date = body.Creation_date
	token.Resended = body.Resended

	// time check
	if crypto.TimePassed(time.Unix(body.Creation_date, 0),
		time.Duration(settings.Conf.Security.Time.LiveTime.VerificationToken)*time.Second) {
		return false, errors.New("live time passed")
	}

	var salt string
	var password_from_db string
	if password == "" {
		err = GetDB().QueryRow("SELECT salt_ FROM verification_codes WHERE verification_code_id_=$1;",
			body.Id).Scan(&salt)
	} else {
		err = GetDB().QueryRow("SELECT salt_, code_ FROM verification_codes WHERE verification_code_id_=$1;",
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
	return verification code
*/
func (token *VerificationToken) New(login string, purpose string, data interface{}) error {
	// gen salts
	var salt = crypto.GenSalt(int(settings.Conf.Security.Token.SaltLength))

	data_bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// insert in database and send verification code
	err = GetDB().QueryRow("INSERT INTO verification_codes (purpose_, data_, code_, salt_) "+
		"VALUES ($1, $2, $3, $4) RETURNING verification_code_id_;",
		purpose,
		string(data_bytes),
		settings.Conf.VerificationCodeSend(login),
		hex.EncodeToString(salt),
	).Scan(&token.Uint64)
	if err != nil {
		return err
	}

	// gen token
	token_body := crypto.VerificationTokenBody{
		Type:          crypto.VERIFICATION_TOKEN_TYPE,
		Id:            token.Uint64,
		Login:         login,
		Creation_date: time.Now().Unix(),
		Resended:      0,
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return err
	}

	return nil
}

func (token *VerificationToken) Update(login Login) error {
	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.VerificationTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return err
		}
		if body.Type != crypto.VERIFICATION_TOKEN_TYPE {
			return errors.New("wrong token type")
		}
		token.Uint64 = body.Id
		token.Creation_date = body.Creation_date
		token.Resended = body.Resended
	}

	if token.Resended >= settings.Conf.Security.Verification.MaxResendCount {
		return errors.New("impossible resending")
	}

	// gen salts
	var salt = crypto.GenSalt(int(settings.Conf.Security.Token.SaltLength))
	// insert salt in database and resend verification code
	_, err := GetDB().Query("UPDATE verification_codes SET code_=$1, salt_=$2 WHERE verification_code_id_=$3;",
		settings.Conf.VerificationCodeSend(login.String), hex.EncodeToString(salt), token.Uint64)
	if err != nil {
		return err
	}

	// gen token
	token.Resended += 1
	token_body := crypto.VerificationTokenBody{
		Type:          crypto.VERIFICATION_TOKEN_TYPE,
		Id:            token.Uint64,
		Login:         login.String,
		Creation_date: time.Now().Unix(),
		Resended:      token.Resended,
	}
	token.String, err = token_body.Gen(salt)
	if err != nil {
		return err
	}

	return nil
}

func (token *VerificationToken) Delete() error {
	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.VerificationTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return err
		}
		if body.Type != crypto.VERIFICATION_TOKEN_TYPE {
			return errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	// insert salt in database and resend verification code
	_, err := GetDB().Query("DELETE FROM verification_codes WHERE verification_code_id_=$1;",
		token.Uint64)
	return err
}

type Purpose struct {
	Name string
	Data string
}

func (token *VerificationToken) GetPurpose() (Purpose, error) {
	var purpose Purpose // will be returned

	// if token is not parsed
	if token.Uint64 == 0 {
		var body crypto.VerificationTokenBody
		err := body.Parse(token.String)
		if err != nil {
			return Purpose{}, err
		}
		if body.Type != crypto.VERIFICATION_TOKEN_TYPE {
			return Purpose{}, errors.New("wrong token type")
		}
		token.Uint64 = body.Id
	}

	// insert salt in database and resend verification code
	err := GetDB().QueryRow("SELECT purpose_, data_ FROM verification_codes WHERE verification_code_id_=$1;",
		token.Uint64).Scan(&purpose.Name, &purpose.Data)
	return purpose, err
}
