package main

import (
	c "Foods/Controllers"
	r "Foods/Routes"
)

func main() {
	c.Controller()
	c.SendExcelFileViaEmail()
	r.WebService()

}
