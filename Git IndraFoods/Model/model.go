package Model

import (
	"mime/multipart"
	"time"

	"github.com/golang-jwt/jwt"
)

type DbConfig struct {
	DBName   string `json:"dbname"`
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
}

type Company struct {
	Cname   string `json:"cname"`
	Address string `json:"address"`
	Phno    int    `json:"phno"`
	Panno   string `json:"panno"`
	Gstno   string `json:"gstno"`
	Logo    string `json:"logo"`
}
type Users_Role struct {
	Uid       int    `json:"uid"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	PhNo      int    `json:"phno"`
	UserName  string `json:"user_name"`
	Password  string `json:"password"`
	IsDeleted string `json:"isdeleted"`
	Cid       int    `json:"cid"`
	Role      string `json:"role"`
}

type Reports struct {
	RepId        int       `json:"id"`
	RepName      string    `json:"rep_name"`
	RepDesc      string    `json:"rep_desc"`
	DailyRuntime string    `json:"daily_runtime"`
	CreatedAt    time.Time `json:"created_at"`
	Location     string    `json:"location"`
	Cid          int       `json:"cid"`
}

type AddReportEmailConfig struct {
	ReportName string `json:"rep_name"`
	RepEmail   string `json:"rep_email"`
	DailyTime  string `json:"daily_time"`
}

type ChangePassword struct {
	Uid     int    `json:"uid"`
	OldPass string `json:"old_password"`
	NewPass string `json:"new_password"`
}

type Claims struct {
	UserName string `json:"username"`
	jwt.StandardClaims
}

type Otp struct {
	Email string `json:"email_id"`
	Otp   string `json:"otp"`
}

type StoreExcelFile struct {
	FileName string         `form:"repname"`
	FileDesc string         `form:"repdesc"`
	File     multipart.File `form:"file"`
}
