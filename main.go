package main

import (
	"fmt"

	"github.com/p2034/universal-password-authentication-server/internal/field"
)

func main() {
	// // initialize database
	// var dbconf cmd.DBConf
	// cmd.ParseConf("./configs/db.local.json", &dbconf)
	// cmd.OpenDB(dbconf)

	// // initialize and start server
	// var serverconf cmd.ServerConf
	// cmd.ParseConf("./configs/server.local.json", &serverconf)
	// cmd.StartServer(serverconf)

	password1 := ""
	cache1 := field.GenPasswordCache(password1)
	fmt.Println(field.CheckPasswordCache(password1, cache1))
	fmt.Println(cache1.Hash, cache1.Iterations, cache1.Salt)
	fmt.Println(len(cache1.Hash), len(cache1.Salt))
}
