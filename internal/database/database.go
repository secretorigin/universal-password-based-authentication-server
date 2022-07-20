package database

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

var DB *sql.DB = nil
var DBmut sync.Mutex

func OpenDB(conf settings.DBConf) {
	connectionsString := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s",
		conf.Host, conf.Port, conf.Name, conf.User, conf.Password)
	// open database
	DB, err := sql.Open("postgres", connectionsString)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	// check database
	err = DB.Ping()
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	log.Println("Connect to the database.")
}
