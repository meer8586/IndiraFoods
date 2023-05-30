package Controllers

import (
	d "Foods/DB"
	m "Foods/Model"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strings"

	"path/filepath"
	"strconv"
	"time"

	b64 "encoding/base64"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"gopkg.in/gomail.v2"
	//"github.com/jasonlvhit/gocron"
)

var (
	jwtKey = []byte("InfobellItSolutions")
	Logger *log.Logger
)

// DB Connection
func Controller() {
	d.DbConn()
}

// log file function
func MyLogger() {
	var logFile = "./ErrorLogFile.log"
	var errorFile, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Println("Error :", err)
	}
	Logger = log.New(errorFile, "ERROR :", log.Ldate|log.Ltime|log.Lshortfile)
}

// ------------------ Login API ----------------

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var usr m.Users_Role
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		Logger.Print(err.Error())
		return
	}

	if usr.UserName == "" || usr.Password == "" {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"Status Code": "202", "Message": "Email/Password Can't be empty"})
		Logger.Print("Email/Password Can't be empty")
		return

	}

	checkUser := "SELECT user_name, password from USERS where user_name = $1 and isdeleted=0"
	rows, err := d.DB.Query(checkUser, usr.UserName)

	fmt.Println(usr.UserName)
	fmt.Println(usr.Password)
	var email, pwd string
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		Logger.Print(err.Error())
		return
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		i++
		rows.Scan(&email, &pwd)
	}
	if i == 0 {
		//w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"Status Code": "202", "Message": "No User Found. Please Check Email and Password.", "Var": "true"})
		Logger.Print("No User Found. Please Check Email OR Password")
		return
	}
	DecPass := PasswordDecoder(pwd)
	if email == usr.UserName && DecPass == usr.Password {

		expirationTime := time.Now().Add(time.Minute * 30)
		claims := &m.Claims{
			UserName: email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)

		if err != nil {
			fmt.Println("Error in generating JWT Err : ", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"Message": "The server encountered an unexpected condition that prevented it from fulfilling the request", "Status Code": "500 "})
			Logger.Print("Error in generating JWT Err", err.Error())
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

		returnUser := "SELECT users.uid ,users.first_name, users.last_name, users.user_name, users.cid, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where user_name=$1;"
		rows1, err := d.DB.Query(returnUser, email)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			Logger.Print(err.Error())
			return
		}
		defer rows1.Close()
		for rows1.Next() {
			rows1.Scan(&usr.Uid, &usr.FirstName, &usr.LastName, &usr.UserName, &usr.Cid, &usr.Role)
		}

		var cname string
		companyName := "Select cname from company_details where cid=$1"
		rows2, err := d.DB.Query(companyName, usr.Cid)
		//fmt.Println(usr.Cid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			Logger.Print(err.Error())
			return
		}
		defer rows2.Close()
		for rows2.Next() {
			rows2.Scan(&cname)
		}
		temp := map[string]interface{}{
			"uid": usr.Uid, "user_name": usr.UserName, "FirstName": usr.FirstName, "LastName": usr.LastName, "CompanyName": cname, "CompanyID": usr.Cid, "Role": usr.Role,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Successfully Logged In", "Token": tokenString, "data": temp})
		return
	} else {
		json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid password", "Var": "true"})
		Logger.Print("Invalid Password")
	}
}

//-----------------------------Add Company API--------------------------------------

func AddCompany(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	//if isValidToken {
	if true {
		var cmp m.Company
		err := json.NewDecoder(r.Body).Decode(&cmp)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			Logger.Print(err.Error())
			return
		}
		insertCmp := "INSERT INTO COMPANY_DETAILS (cname, address, phno, panno, gstno, logo) VALUES($1,$2,$3,$4,$5,$6)"
		_, err = d.DB.Exec(insertCmp, cmp.Cname, cmp.Address, cmp.Phno, cmp.Panno, cmp.Gstno, cmp.Logo)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Company Already Registered With this Name", "Error": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Company Added Successfully !!!"})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//------------------------------------- User's API ------------------------------

// ------------ Get All User API ----------------
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	// if isValidToken {
	if true {
		vars := mux.Vars(r)
		cid, _ := strconv.Atoi(vars["cid"])
		selectAllUsers := "SELECT users.uid, users.first_name, users.last_name, users.user_name, users.isdeleted, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where cid=$1;"

		rows, err := d.DB.Query(selectAllUsers, cid)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		var list []map[string]interface{}
		for rows.Next() {
			var first_name, last_name, user_name, role_name string
			var uid, isdeleted int
			rows.Scan(&uid, &first_name, &last_name, &user_name, &isdeleted, &role_name)
			if isdeleted == 0 {
				temp := map[string]interface{}{
					"UserID": uid, "FirstName": first_name, "LastName": last_name, "Email": user_name, "Role": role_name,
				}
				list = append(list, temp)
				if err != nil {
					w.WriteHeader(http.StatusAccepted)
					json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
					Logger.Print(err.Error())
					return
				}

			}

		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "data": list})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//---------------- Get User Based on Id API ----------------------

func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		user_id, _ := strconv.Atoi(vars["uid"])
		selectUser := "SELECT users.first_name, users.last_name, users.phno, users.user_name , users.isdeleted, users.cid, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where users.uid= $1 and isdeleted=0;"
		var company_id int
		rows, err := d.DB.Query(selectUser, user_id)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		i := 0
		for rows.Next() {
			i++
			var first_name, last_name, phno, username, company_name, role_name string
			var isdeleted int
			rows.Scan(&first_name, &last_name, &phno, &username, &isdeleted, &company_id, &role_name)
			//fmt.Println(company_id)
			//if isdeleted == 0 {
			getCompany := "Select cname from company_details where cid= $1"
			rows, _ = d.DB.Query(getCompany, company_id)
			for rows.Next() {
				rows.Scan(&company_name)
			}

			temp := map[string]interface{}{
				"FirstName": first_name, "LastName": last_name, "PhoneNo": phno, "UserName": username, "CompanyName": company_name, "Role": role_name,
			}

			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
				Logger.Print(err.Error())
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "data": temp})

		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User With this id is not present", "Status Code": "200 "})
			Logger.Print("User With this id is not present")
			return
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------------- Add User API --------------------

func AddUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var usr m.Users_Role
		err := json.NewDecoder(r.Body).Decode(&usr)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		EncPass := PasswordEncoder(usr.Password)

		insertUser := "INSERT INTO USERS (first_name, last_name, phno, user_name, password, cid) VALUES($1,$2,$3,$4,$5,$6)"
		_, err = d.DB.Exec(insertUser, usr.FirstName, usr.LastName, usr.PhNo, usr.UserName, EncPass, usr.Cid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Already Registered With this user_name", "Error": err.Error()})
			Logger.Print("User Already Registered With this user_name", err.Error())
			fmt.Println(err)
			return
		}
		// insertRole := "INSERT INTO ROLE (role_name) VALUES ($1)"
		// _, err = d.DB.Exec(insertRole, usr.Role)

		// if err != nil {
		// 	w.WriteHeader(http.StatusAccepted)
		// 	json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		// 	fmt.Println(err)
		// 	return
		// }

		var usrid, roleid int
		getusrid := "select uid from users where user_name = $1"
		rows, _ := d.DB.Query(getusrid, usr.UserName)
		for rows.Next() {
			rows.Scan(&usrid)
		}
		defer rows.Close()
		//var roleid int
		//getrlid := "select rid from role where role_name = $1"
		getrlid := fmt.Sprintf("select rid from role where role_name= '%s'", usr.Role)
		fmt.Println(getrlid)
		rows1, err := d.DB.Query(getrlid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err)
			return
		}
		defer rows1.Close()
		for rows1.Next() {
			rows1.Scan(&roleid)
		}

		//insertUserWithRole := "INSERT INTO USERS_Role (uid, rid) VALUES($1,$2)"
		insertUser = fmt.Sprintf("Insert into users_role (uid, rid) values(%d,%d)", usrid, roleid)
		fmt.Println(insertUser)
		_, err = d.DB.Exec(insertUser)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "success"})

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//--------------------- Delete User API -------------------------

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		user_id, _ := strconv.Atoi(vars["uid"])
		var usrid int
		getusrid := "select uid from users where uid = $1 and isdeleted=0;"
		rows, _ := d.DB.Query(getusrid, user_id)
		i := 0
		defer rows.Close()
		for rows.Next() {
			i++
			rows.Scan(&usrid)
		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No User Found", "Status Code": "202 "})
			Logger.Print("No User Found")
			return
		}
		deleteUser := "Update users set isdeleted=1 where uid=$1;"
		_, err := d.DB.Exec(deleteUser, user_id)

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Deleted Successfully", "Status Code": "200 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------- Update User Based on Id API ------------------

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		user_id, _ := strconv.Atoi(vars["uid"])

		var user m.Users_Role
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		//updateQuery := "UPDATE USERS SET first_name=$1 , last_name=$2, phno=$3, user_name=$4 where uid=$5"
		updateQuery := fmt.Sprintf("UPDATE USERS SET first_name='%s' , last_name='%s', phno=%d, user_name='%s' where uid=%d", user.FirstName, user.LastName, user.PhNo, user.UserName, user_id)
		fmt.Println(updateQuery)
		_, err = d.DB.Exec(updateQuery)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		var roleid int
		//getrlid := "select rid from role where role_name = $1"
		getrlid := fmt.Sprintf("select rid from role where role_name ='%s'", user.Role)
		fmt.Println(getrlid)
		rows1, _ := d.DB.Query(getrlid)
		for rows1.Next() {
			fmt.Println("Hii")
			rows1.Scan(&roleid)
		}
		defer rows1.Close()
		//updateRole := "UPDATE USERS_ROLE SET RID=$1 WHERE UID = $2 "
		updateRole := fmt.Sprintf("UPDATE USERS_ROLE SET RID=%d WHERE UID = %d", roleid, user_id)
		fmt.Println(updateRole)
		_, err = d.DB.Exec(updateRole)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Record Updated Successfully !", "Status Code": "200 "})

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------------- Reports API -------------------------

//---------------- Get All Reports API --------------

func GetAllReports(w http.ResponseWriter, r *http.Request) {
	var list []m.Reports
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		company_id, _ := strconv.Atoi(vars["cid"])
		selectCid := "select cid from company_details where cid = $1;"
		rows, err := d.DB.Query(selectCid, company_id)
		j := 0
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		for rows.Next() {
			j++
			rows.Scan(&company_id)
		}
		if j == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Company Found", "Status Code": "202 "})
			Logger.Print("No Company Found")
			return
		}

		//selectReports := "SELECT * from report where cid=$1;"
		selectReports := "Select repid, rep_name, rep_desc, location, cid, created_at, daily_runtime from report where cid=$1;"
		rows1, err := d.DB.Query(selectReports, company_id)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows1.Close()
		rep := m.Reports{}
		k := 0
		for rows1.Next() {
			k++
			rows1.Scan(&rep.RepId, &rep.RepName, &rep.RepDesc, &rep.Location, &rep.Cid, &rep.CreatedAt, &rep.DailyRuntime)
			//json.NewEncoder(w).Encode(rep)
			//fmt.Println(rep.DailyRuntime)
			list = append(list, rep)
			fmt.Println(list)
		}
		if k == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Currently No Reports Are Present For The Company", "Status Code": "202 "})
			Logger.Print("Currently No Reports Are Present For The Company.")
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//--------------- Get Report By Name API ---------------------

func GetReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var list []m.Reports
		company_id, _ := strconv.Atoi(vars["cid"])
		repname := vars["repname"]
		if repname == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Provide the Report Name"})
			Logger.Print("Please Provide the Report Name")
			return
		}
		selectQuery := "select cid , rep_name from report where cid = $1 and rep_name = $2;"
		rows, err := d.DB.Query(selectQuery, company_id, repname)
		j := 0
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		for rows.Next() {
			j++
			rows.Scan(&company_id, &repname)
		}
		if j == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Reports Found", "Status Code": "202 "})
			Logger.Print("No Reports Found")
			return
		}

		selectReports := "SELECT repid, rep_name, rep_desc, location, cid, created_at, daily_runtime from report where cid = $1 and rep_name=$2;"
		rows1, err := d.DB.Query(selectReports, company_id, repname)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows1.Close()
		rep := m.Reports{}
		for rows1.Next() {
			rows1.Scan(&rep.RepId, &rep.RepName, &rep.RepDesc, &rep.Location, &rep.Cid, &rep.CreatedAt, &rep.DailyRuntime)
			list = append(list, rep)
		}
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------- Add Report API -----------------

func AddReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var usr m.Reports
		err := json.NewDecoder(r.Body).Decode(&usr)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		insertReport := "INSERT INTO Report (rep_name, rep_desc, daily_runtime, location, cid) VALUES($1,$2,$3,$4,$5)"
		_, err = d.DB.Exec(insertReport, usr.RepName, usr.RepDesc, usr.DailyRuntime, usr.Location, usr.Cid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Report Added Successfully !", "Status Code": "200 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

// ------------------------ Download Report API -----------------------

func DownloadReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var downloadreport m.DownloadReport
		var location string
		err := json.NewDecoder(r.Body).Decode(&downloadreport)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		selectReport := "SELECT location FROM REPORT WHERE repid=$1 and cid=$2; "
		rows, err := d.DB.Query(selectReport, downloadreport.RepId, downloadreport.Cid)
		j := 0
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "msg": "error"})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		for rows.Next() {
			j++
			rows.Scan(&location)
		}
		if j == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Reports Found", "Status Code": "202 "})
			Logger.Print("No Reports Found")
			return
		}

		bytes, err := ioutil.ReadFile(location)
		if err != nil {
			fmt.Println(err.Error())
			Logger.Print(err.Error())
		}

		//var base64Encoding string
		base64EncodingReport := b64.StdEncoding.EncodeToString(bytes)
		//fmt.Println(base64EncodingReport)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Success", "Report": base64EncodingReport})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------------- Report Email Configuration API's ------------------

//--------------- Get All Report Email Config API ------------------

func GetReportEmailConfig(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		company_id, _ := strconv.Atoi(vars["cid"])

		getcid := "select cid from company_details where cid = $1"
		rows, _ := d.DB.Query(getcid, company_id)
		i := 0
		defer rows.Close()
		for rows.Next() {
			i++
			rows.Scan(&company_id)
		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found", "Status Code": "202 "})
			Logger.Print("No Records Found")
			return
		}

		selectAllReportEmailConfig := "SELECT * from report_email_config where isdeleted=0 and cid = $1;"
		rows, err := d.DB.Query(selectAllReportEmailConfig, company_id)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		var list []map[string]interface{}
		j := 0
		for rows.Next() {
			j++
			var eid, isdeleted, rep_send, cid int
			var email, rep_name, daily_time string
			rows.Scan(&eid, &email, &rep_name, &daily_time, &isdeleted, &rep_send, &cid)
			temp := map[string]interface{}{
				"ID": eid, "ReportName": rep_name, "Email": email, "DailyTime": daily_time, "CompanyID": cid,
			}
			//fmt.Println(rep_name)
			list = append(list, temp)
		}
		if j == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found", "Status Code": "202 "})
			Logger.Print("No Records Found")
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------- Get Report Email Config By Id API ------------------

func GetReportEmailConfigById(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		eid, _ := strconv.Atoi(vars["eid"])
		selectCid := "select eid from report_email_config where eid = $1;"
		rows, err := d.DB.Query(selectCid, eid)
		j := 0
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		for rows.Next() {
			j++
			rows.Scan(&eid)
		}
		if j == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found", "Status Code": "202 "})
			Logger.Print("No Records Found")
			return
		}
		//selectReportEmailConfig := "SELECT * from report_email_config where eid=$1;"
		selectReportEmailConfig := fmt.Sprintf("SELECT * from report_email_config where eid=%d and isdeleted=0", eid)
		rows1, err := d.DB.Query(selectReportEmailConfig)

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows1.Close()
		var temp m.AddReportEmailConfig
		i := 0
		for rows1.Next() {

			i++
			err = rows1.Scan(&temp.Eid, &temp.RepEmail, &temp.ReportName, &temp.DailyTime, &temp.IsDeleted, &temp.RepSend, &temp.Cid)

		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Rows Returned", "Status Code": "202 "})
			Logger.Print("No Rows Returned")
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": temp})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//----------------- Add Report Email Config API ------------------

func AddReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		company_id, _ := strconv.Atoi(vars["cid"])

		var repemail m.AddReportEmailConfig
		err := json.NewDecoder(r.Body).Decode(&repemail)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		insertReportEmailConfig := "INSERT INTO report_email_config (email, rep_name, daily_time, cid) VALUES($1,$2,$3, $4)"
		_, err = d.DB.Exec(insertReportEmailConfig, repemail.RepEmail, repemail.ReportName, repemail.DailyTime, company_id)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "success"})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//------------- Update Report Email Config By ID API ----------------

func UpdateReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		eid, _ := strconv.Atoi(vars["eid"])
		var repEmail m.AddReportEmailConfig

		err := json.NewDecoder(r.Body).Decode(&repEmail)
		if err != nil {
			log.Fatalln("There was an error decoding the request body into the struct")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		//updateQuery := "UPDATE USERS SET first_name=$1 , last_name=$2, phno=$3, user_name=$4 where uid=$5"
		updateQuery := fmt.Sprintf("UPDATE report_email_config SET email='%s', rep_name='%s', daily_time='%s' where eid=%d", repEmail.RepEmail, repEmail.ReportName, repEmail.DailyTime, eid)
		fmt.Println(updateQuery)
		_, err = d.DB.Exec(updateQuery)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Record Updated Successfully !!!", "Status Code": "200 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

//--------------- Delete Record Email Config By Id API -----------------

func DeleteReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		vars := mux.Vars(r)
		eid, _ := strconv.Atoi(vars["eid"])

		seletQuery := "select eid from report_email_config where eid = $1 and isdeleted=0;"
		rows, _ := d.DB.Query(seletQuery, eid)
		i := 0
		var isdeleted int
		defer rows.Close()
		for rows.Next() {
			i++
			rows.Scan(&eid, &isdeleted)
		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found", "Status Code": "202 "})
			Logger.Print("No Records Found")
			return
		}
		deleteUser := "Update report_email_config set isdeleted=1 where eid=$1;"
		_, err := d.DB.Exec(deleteUser, eid)
		//fmt.Println(company_id)

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Deleted Successfully", "Status Code": "200 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

// Change Password API

func ChangePass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var data m.ChangePassword
		var pass string
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalln("There was an error decoding the request body into the struct", err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		changePass := "SELECT password from USERS WHERE uid = $1 and isdeleted=0;"
		rows, err := d.DB.Query(changePass, data.Uid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		i := 0
		for rows.Next() {
			i++
			rows.Scan(&pass)
		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No User Found", "Status Code": "202 "})
			Logger.Print("No User Found")
			return
		}
		pass2 := PasswordDecoder(pass)
		fmt.Println(data.Uid)
		fmt.Println(pass)
		fmt.Println(pass2)
		if pass2 != data.OldPass {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid Old Password", "Status Code": "202 "})
			Logger.Print("Invalid Old Password")
			return
		}
		EncPass := PasswordEncoder(data.NewPass)
		changePass2 := "UPDATE USERS SET PASSWORD=$1 WHERE UID=$2"
		_, err = d.DB.Exec(changePass2, EncPass, data.Uid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Password Updated Successfully !!!", "Status Code": "202 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

// ------------------- Forgot Password API ------------------

var OTP string
var OTPExpiration time.Time

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var usr m.Users_Role
		var email string
		err := json.NewDecoder(r.Body).Decode(&usr)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		checkMail := "SELECT user_name from USERS WHERE user_name=$1 and isdeleted=0;"

		fmt.Println(usr.UserName)
		rows, err := d.DB.Query(checkMail, usr.UserName)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		defer rows.Close()
		i := 0
		for rows.Next() {
			i++
			rows.Scan(&email)
		}
		if i == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found With this Email", "Status Code": "202 "})
			Logger.Print("No Records Found With This Email")
			return
		}

		otp := strconv.Itoa(generateOTP()) // convert the integer OTP to a string
		OTP = otp
		fmt.Println(otp)
		// Set OTP expiration time
		err = sendOTP(email, otp)
		if err != nil {
			fmt.Println("Error sending OTP:", err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 "})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

func generateOTP() int {
	rand.Seed(time.Now().UnixNano())
	OTPExpiration = time.Now().Add(1 * time.Minute)
	return rand.Intn(900000) + 100000 // generate a random 6-digit integer
}

func sendOTP(email, otp string) error {
	auth := smtp.PlainAuth("", "msyed@infobellit.com", "cpadrodiolwdbdat", "smtp.gmail.com")

	msg := []byte("To: " + email + "\r\n" +
		"Subject: Forgot PassWord\r\n" +
		"\r\n" +
		"Your OTP is: " + otp + "\r\n")

	err := smtp.SendMail("smtp.gmail.com:587", auth, "msyed@infobellit.com", []string{email}, msg)
	if err != nil {

		return err
	}

	return nil
}

func VerifyOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		currentTime := time.Now()
		var verifyotp m.Otp
		err := json.NewDecoder(r.Body).Decode(&verifyotp)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		if currentTime.After(OTPExpiration) { // Check if OTP has expired
			json.NewEncoder(w).Encode(map[string]string{"Message": "OTP expired"})
			Logger.Print("OTP Expired")
			return
		}

		// id := r.URL.Query().Get("otp")

		if verifyotp.Otp != OTP {
			json.NewEncoder(w).Encode(map[string]string{"Message": "invalid otp"})
			Logger.Print("Invalid OTP")
		} else {
			json.NewEncoder(w).Encode(map[string]string{"Message": "otp verified"})
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

func ResetPass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if true {
		var usr m.Users_Role
		err := json.NewDecoder(r.Body).Decode(&usr)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		EncPass := PasswordEncoder(usr.Password)

		sqlStatement := `
    UPDATE users
    SET password = $1
    WHERE user_name = $2`

		_, err = d.DB.Exec(sqlStatement, EncPass, usr.UserName)

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		} else {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"Message": "password updated"})
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

func StoreReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		vars := mux.Vars(r)
		cid, _ := strconv.Atoi(vars["cid"])
		//fmt.Println("hii")
		var sf m.StoreExcelFile
		//err := json.NewDecoder(r.Body).Decode(&sf)
		err := r.ParseMultipartForm(32 << 20)

		if err != nil {
			http.Error(w, "Failed to retrieve file from form data", http.StatusBadRequest)
			Logger.Print("Failed to retrieve file from form data")
			return
		}

		sf.FileName = r.FormValue("repname")
		sf.FileDesc = r.FormValue("repdesc")
		sf.File, _, _ = r.FormFile("file")

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		fmt.Println("hii")
		filePath, err := saveExcelFile(sf)
		//fmt.Println("after hii")
		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			Logger.Print(err.Error())
			return
		}

		// Store the file path in PostgreSQL
		query := "INSERT INTO REPORT (rep_name, rep_desc, location, cid) VALUES ($1,$2,$3,$4)"
		_, err = d.DB.Exec(query, sf.FileName, sf.FileDesc, filePath, cid)
		fmt.Println(filePath)
		fmt.Println("hii")
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"Message": "Report Added Successfully"})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}

func saveExcelFile(sf m.StoreExcelFile) (string, error) {

	todaystime := time.Now().Format("2006-01-02")
	filename := sf.FileName + "_" + todaystime + ".xlsx"

	// Define the destination path on the file server
	destPath := filepath.Join("./Reports", filename)
	fmt.Println(filename)
	fmt.Println("Hii")
	// Read the contents of the file
	fileBytes, err := ioutil.ReadAll(sf.File)
	if err != nil {
		fmt.Println("in read")
		Logger.Print(err.Error())
		return "", err
	}
	fmt.Println("file bytes hii")

	// Write the file to the file server
	err = ioutil.WriteFile(destPath, fileBytes, 0644)
	if err != nil {
		fmt.Println(err)
		fmt.Println("hii")
		Logger.Print(err.Error())
		return "", err
	}
	fmt.Println("Report added successfully")
	fmt.Println(destPath)
	return destPath, nil
}

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

// Function For Password Encoding
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

func VerifyToken(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		//fmt.Fprint(w, "Missing Authorization header")
		return false
	}
	// Extract the token from the header
	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Set the token signing key or retrieve it from a secure location
		// For example, you can return a byte array containing your secret key
		// or fetch it from a configuration file or environment variable.
		secretKey := []byte(jwtKey)
		return secretKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		Logger.Print("Invalid Token")
		return false
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	// cookie, err := r.Cookie("token")
	// if err != nil {
	// 	if err == http.ErrNoCookie {
	// 		w.WriteHeader(http.StatusUnauthorized)
	// 		return false
	// 	}
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return false
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
	// 		return false
	// 	}
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return false
	// }

	// if !tkn.Valid {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return false
	// }
	// // if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {

	// // }

	// expirationTime := time.Now().Add(time.Minute * 5)

	// claims.ExpiresAt = expirationTime.Unix()

	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// tokenString, err := token.SignedString(jwtKey)

	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return false
	// }

	// http.SetCookie(w,
	// 	&http.Cookie{
	// 		Name:    "refresh_token",
	// 		Value:   tokenString,
	// 		Expires: expirationTime,
	// 	})

	// return true
	return true
}
