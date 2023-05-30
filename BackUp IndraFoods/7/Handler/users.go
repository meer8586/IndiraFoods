package Handler

import (
	d "Foods/DB"
	m "Foods/Model"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

// ---------------- Login User API ------------------

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

//------------------------------------- User's API ------------------------------

// ------------ Get All User API ----------------
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
		vars := mux.Vars(r)
		cid, _ := strconv.Atoi(vars["cid"])
		page, _ := strconv.Atoi(vars["page"])
		limit, _ := strconv.Atoi(vars["limit"])
		if page < 1 {
			page = 1

		}
		if limit < 1 {
			limit = 10
		}
		offset := (page - 1) * limit
		i := 0
		selectComp := "SELECT CID FROM COMPANY_DETAILS WHERE CID = $1;"
		rows1, err := d.DB.Query(selectComp, cid)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
		}
		for rows1.Next() {
			i++
			rows1.Scan(&cid)
		}
		if i == 0 {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Company Found With This ID"})
			return
		}
		count := 0
		selectCount := "SELECT COUNT(*) FROM USERS where cid=$1 and isdeleted=0;"
		rows2, err := d.DB.Query(selectCount, cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		for rows2.Next() {
			rows2.Scan(&count)
		}
		selectAllUsers := "SELECT users.uid, users.first_name, users.last_name, users.user_name, users.isdeleted, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where cid=$1 and isdeleted=0 limit $2 offset $3;"
		j := 0
		rows, err := d.DB.Query(selectAllUsers, cid, limit, offset)
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
			j++
			var first_name, last_name, user_name, role_name string
			var uid, isdeleted int
			rows.Scan(&uid, &first_name, &last_name, &user_name, &isdeleted, &role_name)

			temp := map[string]interface{}{
				"UserID": uid, "FirstName": first_name, "LastName": last_name, "Email": user_name, "Role": role_name, //"Page": page, "Limit": limit, "Count": count,
			}
			list = append(list, temp)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
				Logger.Print(err.Error())
				return
			}

		}
		//fmt.Println(j)
		if j == 0 {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "data": "Currently No Users Are Registered With This Company"})
			return
		}
		totalPage := math.Ceil(float64(count) / float64(limit))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "data": list, "pageNo": page, "limit": limit, "totalItems": count, "totalPage": totalPage})

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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
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
			w.WriteHeader(http.StatusOK)
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}
		fmt.Println(userName)
		desc := userName + " Added " + usr.UserName + " In Users Table"
		fmt.Println(desc)
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "INSERT", desc, usr.Cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err.Error())
		}
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		vars := mux.Vars(r)
		user_id, _ := strconv.Atoi(vars["uid"])
		var usrid, cid int
		var user_name string
		getusrid := "select uid, user_name, cid from users where uid = $1 and isdeleted=0;"
		rows, _ := d.DB.Query(getusrid, user_id)
		i := 0
		defer rows.Close()
		for rows.Next() {
			i++
			rows.Scan(&usrid, &user_name, &cid)
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " DELETED " + user_name + " From Users Table"
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "DELETE", desc, cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err.Error())
		}
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

		var cid int
		selectCid := "select cid from users where uid =$1;"
		rows, _ := d.DB.Query(selectCid, user_id)
		for rows.Next() {
			rows.Scan(&cid)
		}
		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Updated " + user.UserName + " In Users Table"
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "INSERT", desc, cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err.Error())
		}
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		var data m.ChangePassword
		var username, pass string
		var cid int
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			log.Fatalln("There was an error decoding the request body into the struct", err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		changePass := "SELECT user_name, password, cid from USERS WHERE uid = $1 and isdeleted=0;"
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
			rows.Scan(&username, &pass, &cid)
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Changed Password of " + username
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "UPDATE", desc, cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			fmt.Println(err.Error())
		}
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

			var cid int
			selectCid := "select cid from users where user_name =$1;"
			rows, _ := d.DB.Query(selectCid, usr.UserName)
			for rows.Next() {
				rows.Scan(&cid)
			}
			userName, er := extractUserNameFromToken(tokenString)
			if er != nil {
				Logger.Print(er.Error())
			}

			desc := userName + " Resets Password Successfully of " + usr.UserName + " in Users Table"
			insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
			_, err = d.DB.Exec(insertAudit, userName, "UPDATE", desc, cid)
			if err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
				Logger.Print(err.Error())
				fmt.Println(err.Error())
			}

		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Please Login First"})
		Logger.Print("Please Login First")
	}
}
