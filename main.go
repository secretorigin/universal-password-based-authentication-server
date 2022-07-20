package main

import (
	"github.com/p2034/universal-password-based-authentication-server/cmd"
	"github.com/p2034/universal-password-based-authentication-server/internal/database"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func main() {
	// initialize database
	var dbconf settings.DBConf
	settings.ParseConf("./configs/db.local.json", &dbconf)
	database.OpenDB(dbconf)

	// initialize and start server
	var serverconf settings.ServerConf
	settings.ParseConf("./configs/server.local.json", &serverconf)
	cmd.StartServer(serverconf)
}
