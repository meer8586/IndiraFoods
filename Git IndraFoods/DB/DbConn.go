package DB

import (
	d "Foods/Model"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB
var config d.DbConfig

func DbConn() {
	file1, err := os.Open("./DB/connectDetails.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file1.Close()

	decoder := json.NewDecoder(file1)
	config = d.DbConfig{}
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatal("Failed to parse configuration file: ", err)
	}

	dsn := "host=" + config.Host + " port=" + config.Port + " user=" + config.User + " password=" + config.Password + " dbname=" + config.DBName + " sslmode=disable"
	fmt.Println(dsn)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	fmt.Println("Database Connected Successfully !!!")
	DB = db
}
