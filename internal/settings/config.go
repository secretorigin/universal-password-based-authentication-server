package settings

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type DBConf struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type ServerConf struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ServerSettingsConf struct {
	// function for sending verification code
	VerificationCodeSend func(string) string `json:"-"`

	// print all errors and debug messages
	DebugMode bool `json:"debug-mode"`

	// properties
	Verification struct {
		PasswordChange bool `json:"password-change"`
		LoginChange    bool `json:"login-change"`
		UserCreate     bool `json:"user-create"`
		UserDelete     bool `json:"user-delete"`
		TokenGet       bool `json:"token-get"`
	} `json:"verification"`
	Regex struct {
		VerificationCode string `json:"verification-code"`
		Login            string `json:"login"`
		Password         string `json:"password"`
		Token            string `json:"token"`
	} `json:"regex"`
	Security struct {
		Password struct {
			MinIterations uint32 `json:"min-iterations"`
			HashLength    uint32 `json:"hash-length"`
			SaltLength    uint32 `json:"salt-length"`
		} `json:"password"`
		Token struct {
			SaltLength uint32 `json:"salt-length"`
		} `json:"token"`
		Time struct {
			MaxResponse uint32 `json:"max-response"` // must be in milliseconds
		}
	} `json:"security"`
}

var Conf ServerSettingsConf

// parse config from file
func ParseConf(path string, conf interface{}) {
	jsonFile, err := os.Open(path)
	if err != nil {
		log.Println(err.Error())
		return
	}
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Println(err.Error())
		return
	}
	err = json.Unmarshal(byteValue, conf)
	if err != nil {
		log.Println(err.Error())
		return
	}
}
