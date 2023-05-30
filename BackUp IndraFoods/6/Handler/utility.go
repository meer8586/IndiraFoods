package Handler

import (
	d "Foods/DB"
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"gopkg.in/gomail.v2"
)

var (
	jwtKey = []byte("InfobellItSolutions")
	Logger *log.Logger
)

// log file function
func MyLogger() {
	var logFile = "./ErrorLogFile.log"
	var errorFile, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Println("Error :", err)
	}
	Logger = log.New(errorFile, "ERROR :", log.Ldate|log.Ltime|log.Lshortfile)
}

// Function to Send Excel Files Via Mail

func SendExcelFileViaEmail() {
	//defer wg.Done()
	query := "SELECT DAILY_TIME FROM report_email_config ORDER BY DAILY_TIME ASC;"
	rows, err := d.DB.Query(query)
	if err != nil {
		Logger.Print(err.Error())
		fmt.Println(err)
	}
	var daily_time, emailid, repname, location string
	var parsedTime time.Time
	todaysdate := time.Now().Format("2006-01-02")
	i := 0
	for rows.Next() {
		i++
		rows.Scan(&daily_time)
		//fmt.Println(daily_time)
		parsedTime, err = time.Parse("3:04 PM", daily_time)
		outputTime := parsedTime.Format("15:04")

		if err != nil {
			fmt.Println("Invalid input time:", err)
			Logger.Print("Invalid Input Time ", err.Error())
			return
		}

		current_time := time.Now().Format("3:04 PM")
		parsedCurrentTime, err := time.Parse("3:04 PM", current_time)
		parsedCurrentTime2 := parsedCurrentTime.Format("15:04")
		if err != nil {
			fmt.Println("Invalid input time:", err)
			Logger.Print("Invalid Input Time ", err.Error())
			return
		}
		fmt.Println(parsedCurrentTime2)
		//fmt.Println(parsedTime)

		fmt.Println("Converted time:", outputTime)

		if parsedCurrentTime2 == outputTime {

			query2 := "SELECT email, rep_name FROM report_email_config where daily_time=$1 and rep_send=0;"
			rows1, err := d.DB.Query(query2, daily_time)
			if err != nil {
				Logger.Print(err.Error())
				fmt.Println(err)
			}
			for rows1.Next() {
				rows1.Scan(&emailid, &repname)
				fmt.Println(emailid)
				fmt.Println("--------------------------------")

				query3 := "SELECT location FROM report where rep_name=$1 and created_at=$2;"
				rows2, err := d.DB.Query(query3, repname, todaysdate)
				if err != nil {
					Logger.Print(err.Error())
					fmt.Println(err)
				}
				for rows2.Next() {
					rows2.Scan(&location)
				}

				fmt.Println("hii")
				m := gomail.NewMessage()
				m.SetHeader("From", "msyed@infobellit.com")
				m.SetHeader("To", emailid)
				m.SetHeader("Subject", "Daily Report")
				//m.SetBody("text/html", "Hello <b>Bob</b> and <i>Cora</i>!")
				m.Attach(location)
				db := d.DB
				d := gomail.NewDialer("smtp.gmail.com", 587, "msyed@infobellit.com", "cpadrodiolwdbdat")
				d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

				if err := d.DialAndSend(m); err != nil {
					fmt.Print(err)
					Logger.Print(err.Error())

				} else {
					fmt.Println("sent")
					updateRecord := "Update report_email_config set rep_send=1 where email=$1 and rep_name=$2;"
					db.Exec(updateRecord, emailid, repname)
				}

			}

		}
	}
	if i == 0 {
		fmt.Println("No Reports Are Found To Mail")
		Logger.Print("No Reports Found ")
		return
	}

}

// Function To Encode The Password

func PasswordEncoder(password string) string {
	EncPass := b64.RawStdEncoding.EncodeToString([]byte(password))
	fmt.Println(EncPass)
	return EncPass
}

// Function to Decode the Password

func PasswordDecoder(password string) string {
	DecPass, err := b64.RawStdEncoding.DecodeString((password))
	if err != nil {
		Logger.Print(err.Error())
	}
	fmt.Println(DecPass)
	return string(DecPass)
}

// Function to Verify the JWT token

func VerifyToken(w http.ResponseWriter, r *http.Request) (bool, string) {
	tokenString := "abcd"
	// authHeader := r.Header.Get("Authorization")
	// if authHeader == "" {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	//fmt.Fprint(w, "Missing Authorization header")
	// 	return false, ""
	// }
	// // Extract the token from the header
	// tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	// token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	// 	// Set the token signing key or retrieve it from a secure location
	// 	// For example, you can return a byte array containing your secret key
	// 	// or fetch it from a configuration file or environment variable.
	// 	secretKey := []byte(jwtKey)
	// 	return secretKey, nil
	// })
	// if err != nil {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	fmt.Fprint(w, "Invalid token")
	// 	Logger.Print("Invalid Token")
	// 	return false, ""
	// }
	// if !token.Valid {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return false, ""
	// }
	return true, tokenString

	// cookie, err := r.Cookie("token")
	// if err != nil {
	// 	if err == http.ErrNoCookie {
	// 		w.WriteHeader(http.StatusUnauthorized)
	// 		return false, ""
	// 	}
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return false, ""
	// }
	// tokenStr := cookie.Value

	// claims := &m.Claims{}
	// tkn, err := jwt.ParseWithClaims(tokenStr, claims,
	// 	func(t *jwt.Token) (interface{}, error) {
	// 		return jwtKey, nil
	// 	})
	// if err != nil {
	// 	if err == jwt.ErrSignatureInvalid {
	// 		w.WriteHeader(http.StatusUnauthorized)
	// 		return false, ""
	// 	}
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return false, ""
	// }

	// if !tkn.Valid {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return false, ""
	// }
	// // if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {

	// // }

	// expirationTime := time.Now().Add(time.Minute * 5)

	// claims.ExpiresAt = expirationTime.Unix()

	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// tokenString, err := token.SignedString(jwtKey)

	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return false, ""
	// }

	// http.SetCookie(w,
	// 	&http.Cookie{
	// 		Name:    "refresh_token",
	// 		Value:   tokenString,
	// 		Expires: expirationTime,
	// 	})

	// return true, tokenString
}

// Function to extract the user name from the token

func extractUserNameFromToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Replace "your_secret_key" with the actual secret key used to sign the token
		return []byte(jwtKey), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userName := claims["username"]
		userName2 := userName.(string)
		fmt.Println(userName2)
		return userName2, nil
	}

	return "", fmt.Errorf("invalid token")
}
