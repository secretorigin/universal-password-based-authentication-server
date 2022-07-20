package cmd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

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
