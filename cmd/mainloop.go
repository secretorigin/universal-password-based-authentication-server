package cmd

import (
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
	StartServer(serverconf)
}

func StartServer(conf settings.ServerConf) {
	settings.DebugMode = true
	http.HandleFunc("/user/create", requests.UserCreateHandler)
	http.HandleFunc("/user/delete", requests.UserDeleteHandler)
	http.HandleFunc("/token/get", requests.TokenGetHandler)

	host := fmt.Sprintf("%s:%d", conf.Host, conf.Port)

	log.Println("Server is listening on host: " + host)
	http.ListenAndServe(host, nil)
}
