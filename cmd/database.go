package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
)

type DBConf struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
}

var DB *sql.DB = nil
var DBmut sync.Mutex

func OpenDB(conf DBConf) {
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
