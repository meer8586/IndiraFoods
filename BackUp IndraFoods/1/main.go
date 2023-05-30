package main

import (
	c "Foods/Controllers"
	r "Foods/Routes"
	"time"

	"github.com/go-co-op/gocron"
)

func main() {
	c.Controller()
	s := gocron.NewScheduler(time.UTC)
	s.Every("1m").Do(c.SendExcelFileViaEmail)
	s.StartAsync()
	r.WebService()

}
