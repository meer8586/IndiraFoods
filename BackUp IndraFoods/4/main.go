package main

import (
	c "Foods/Controllers"
	r "Foods/Routes"
	"time"

	"github.com/go-co-op/gocron"
)

func main() {
	c.Controller()
	c.MyLogger()
	s := gocron.NewScheduler(time.UTC)
	now := time.Now()
	nextSchedule := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	s.Every(1).Minute().StartAt(nextSchedule).Do(c.SendExcelFileViaEmail)
	s.StartAsync()
	r.WebService()

}
