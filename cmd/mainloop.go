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

	// get server properties
	settings.ParseConf("./configs/server.json", &settings.Conf)

	// initialize and start server
	var serverconf settings.ServerConf
	settings.ParseConf("./configs/server.local.json", &serverconf)
	setVariables()
	startServer(serverconf)
}

func startServer(conf settings.ServerConf) {
	// handlers
	http.HandleFunc("/user/create", requests.Handler(requests.User_create))
	http.HandleFunc("/user/delete", requests.Handler(requests.User_delete))
	http.HandleFunc("/password/change", requests.Handler(requests.Password_change))
	http.HandleFunc("/login/change", requests.Handler(requests.Login_change))

	http.HandleFunc("/token/get", requests.Handler(requests.Token_get))
	http.HandleFunc("/token/delete", requests.Handler(requests.Token_delete))
	http.HandleFunc("/token/check", requests.Handler(requests.Token_check))
	http.HandleFunc("/token/update", requests.Handler(requests.Token_update))

	http.HandleFunc("/confirm", requests.Handler(requests.Confirm))

	// start server
	host := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	log.Println("Server is listening on host: " + host)
	http.ListenAndServe(host, nil)
}

func setVariables() {
	settings.Conf.VerificationCodeSend = func(login string) string {
		bytes := make([]byte, 4)
		rand.Read(bytes)
		code := hex.EncodeToString(bytes)
		log.Println(fmt.Sprintf("For login: %s, verification code is: %s", login, code))
		return code
	}
}
