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
