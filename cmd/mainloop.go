package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/requests"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func Start() {
	// initialize database
	var dbconf settings.DBConf
	settings.ParseConf("./configs/db.local.json", &dbconf)
	database.OpenDB(dbconf)

	// initialize and start server
	var serverconf settings.ServerConf
	settings.ParseConf("./configs/server.local.json", &serverconf)
	setVariables()
	startServer(serverconf)
}

func startServer(conf settings.ServerConf) {
	// handlers
	http.HandleFunc("/user/create", requests.UserCreateHandler)
	http.HandleFunc("/user/delete", requests.UserDeleteHandler)
	http.HandleFunc("/password/change", requests.PasswordChangeHandler)
	http.HandleFunc("/login/change", requests.LoginChangeHandler)

	http.HandleFunc("/token/get", requests.TokenGetHandler)
	http.HandleFunc("/token/delete", requests.TokenDeleteHandler)
	http.HandleFunc("/token/check", requests.TokenCheckHandler)
	http.HandleFunc("/token/update", requests.TokenUpdateHandler)

	http.HandleFunc("/confirm", requests.ConfirmHandler)

	// start server
	host := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	log.Println("Server is listening on host: " + host)
	http.ListenAndServe(host, nil)
}

func setVariables() {
	settings.DebugMode = true

	settings.TemporaryPasswordSend = func(login string) string {
		bytes := make([]byte, 4)
		rand.Read(bytes)
		code := hex.EncodeToString(bytes)
		log.Println("Temporary password for login:", login, code)
		return code
	}
	settings.TemporaryPasswordRegex = ""

	settings.UserCreate2FA = true
	settings.PasswordChange2FA = true
	settings.LoginChange2FA = true
	settings.UserDelete2FA = true
	settings.TokenGet2FA = true
}
