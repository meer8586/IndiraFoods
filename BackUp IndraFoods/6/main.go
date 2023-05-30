package main

import (
	d "Foods/DB"
	h "Foods/Handler"
	r "Foods/Routes"
	"time"

	"github.com/go-co-op/gocron"
)

func main() {
	d.DbConn()
	h.MyLogger()
	s := gocron.NewScheduler(time.UTC)
	now := time.Now()
	nextSchedule := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 50, now.Location())
	s.Every(1).Minute().StartAt(nextSchedule).Do(h.SendExcelFileViaEmail)
	s.StartAsync()
	r.WebService()

}
