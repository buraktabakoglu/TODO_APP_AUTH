package main

import (
	
	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg"
	

	_ "github.com/jinzhu/gorm/dialects/postgres"
	
)

// @title Go + Gin Todo API
// @version 1.0

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8081
// @BasePath /
// @query.collection.format multi

func main () {

	pkg.Run()
}


