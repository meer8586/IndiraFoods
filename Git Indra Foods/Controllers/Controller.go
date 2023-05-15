package Controllers

import (
	d "Foods/DB"
	m "Foods/Model"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	b64 "encoding/base64"

	"github.com/gorilla/mux"
)

func Controller() {
	d.DbConn()
}

//-----------------------------Add Company API--------------------------------------

func AddCompany(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	var cmp m.Company
	err := json.NewDecoder(r.Body).Decode(&cmp)
	if err != nil {
		fmt.Println(err)

		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400 Bad Request", "Message": err})
		return
	}
	insertCmp := "INSERT INTO COMPANY_DETAILS (cname, address, phno, panno, gstno, logo) VALUES($1,$2,$3,$4,$5,$6)"
	_, err = d.DB.Exec(insertCmp, cmp.Cname, cmp.Address, cmp.Phno, cmp.Panno, cmp.Gstno, cmp.Logo)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Company Already Registered With this Name", "Status Code": "202 "})
		fmt.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "Company Added Successfully !!!"})
}

//------------------------------------- User's API ------------------------------

// ------------ Get All User API ----------------
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	selectAllUsers := "SELECT users.first_name, users.last_name, users.user_name, users.isdeleted, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid;"

	rows, err := d.DB.Query(selectAllUsers)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
	}
	var list []map[string]interface{}
	for rows.Next() {
		var first_name, last_name, user_name, role_name string
		var isdeleted int
		rows.Scan(&first_name, &last_name, &user_name, &isdeleted, &role_name)
		if isdeleted == 0 {
			temp := map[string]interface{}{
				"FirstName": first_name, "LastName": last_name, "Email": user_name, "Role": role_name,
			}
			list = append(list, temp)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}

		}

	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})
}

//---------------- Get User Based on Id API ----------------------

func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	user_id, _ := strconv.Atoi(vars["uid"])
	selectUser := "SELECT users.first_name, users.last_name, users.phno, users.user_name , users.isdeleted, users.cid, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where users.uid= $1 and isdeleted=0;"
	var company_id int
	rows, err := d.DB.Query(selectUser, user_id)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
	}
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
			"FirstName": first_name, "LastName": last_name, "Phone No": phno, "User Name": username, "Company Name": company_name, "Role": role_name,
		}

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": temp})

		// } else {
		// 	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User With this id is not present", "Status Code": "200 "})
		// }

	}
	if i == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User With this id is not present", "Status Code": "200 "})
	}

}

//----------------------- Add User API --------------------

func AddUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	var usr m.Users_Role
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400 Bad Request", "Message": err})
		return
	}
	EncPass := PasswordEncoder(usr.Password)

	insertUser := "INSERT INTO USERS (first_name, last_name, phno, user_name, password, cid) VALUES($1,$2,$3,$4,$5,$6)"
	_, err = d.DB.Exec(insertUser, usr.FirstName, usr.LastName, usr.PhNo, usr.UserName, EncPass, usr.Cid)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Already Registered With this user_name", "Status Code": "202 "})
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
	//var roleid int
	//getrlid := "select rid from role where role_name = $1"
	getrlid := fmt.Sprintf("select rid from role where role_name= '%s'", usr.Role)
	fmt.Println(getrlid)
	rows1, err := d.DB.Query(getrlid)
	if err != nil {
		log.Fatal(err)
	}
	for rows1.Next() {
		rows1.Scan(&roleid)
	}

	//insertUserWithRole := "INSERT INTO USERS_Role (uid, rid) VALUES($1,$2)"
	insertUser = fmt.Sprintf("Insert into users_role (uid, rid) values(%d,%d)", usrid, roleid)
	fmt.Println(insertUser)
	_, err = d.DB.Exec(insertUser)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		fmt.Println(err)
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "success"})

}

//--------------------- Delete User API -------------------------

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	user_id, _ := strconv.Atoi(vars["uid"])

	deleteUser := "Update users set isdeleted=1 where uid=$1;"
	_, err := d.DB.Exec(deleteUser, user_id)

	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Deleted Successfully", "Status Code": "200 "})
}

//----------------- Update User Based on Id API ------------------

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	user_id, _ := strconv.Atoi(vars["uid"])

	var user m.Users_Role
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Fatalln("There was an error decoding the request body into the struct")
	}

	//updateQuery := "UPDATE USERS SET first_name=$1 , last_name=$2, phno=$3, user_name=$4 where uid=$5"
	updateQuery := fmt.Sprintf("UPDATE USERS SET first_name='%s' , last_name='%s', phno=%d, user_name='%s' where uid=%d", user.FirstName, user.LastName, user.PhNo, user.UserName, user_id)
	fmt.Println(updateQuery)
	_, err = d.DB.Exec(updateQuery)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
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
	//updateRole := "UPDATE USERS_ROLE SET RID=$1 WHERE UID = $2 "
	updateRole := fmt.Sprintf("UPDATE USERS_ROLE SET RID=%d WHERE UID = %d", roleid, user_id)
	fmt.Println(updateRole)
	_, err = d.DB.Exec(updateRole)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Record Updated Successfully !", "Status Code": "200 "})

}

//----------------------- Reports API -------------------------

//---------------- Get All Reports API --------------

func GetAllReports(w http.ResponseWriter, r *http.Request) {
	var list []m.Reports
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	company_id, _ := strconv.Atoi(vars["cid"])

	//selectReports := "SELECT * from report where cid=$1;"
	selectReports := "Select * from report where cid=$1;"
	rows, err := d.DB.Query(selectReports, company_id)
	if err != nil {
		log.Fatal(err)
	}
	rep := m.Reports{}
	for rows.Next() {
		rows.Scan(&rep.RepId, &rep.RepName, &rep.RepDesc, &rep.DailyRuntime, &rep.CreatedAt, &rep.Location, &rep.Cid)
		//json.NewEncoder(w).Encode(rep)
		list = append(list, rep)
		fmt.Println(list)
	}
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})
}

//--------------- Get Report By Name API ---------------------

func GetReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var list []m.Reports
	company_id, _ := strconv.Atoi(vars["cid"])
	repname := vars["repname"]

	selectReports := "SELECT * from report where cid = $1 and rep_name=$2;"
	rows, err := d.DB.Query(selectReports, company_id, repname)
	if err != nil {
		log.Fatal(err)
	}
	rep := m.Reports{}
	for rows.Next() {

		rows.Scan(&rep.RepId, &rep.RepName, &rep.RepDesc, &rep.DailyRuntime, &rep.CreatedAt, &rep.Location, &rep.Cid)
		list = append(list, rep)

	}
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})

}

//----------------- Add Report API -----------------

func AddReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	var usr m.Reports
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400 Bad Request", "Message": err})
		return
	}

	insertReport := "INSERT INTO Report (rep_name, rep_desc, daily_runtime, location, cid) VALUES($1,$2,$3,$4,$5)"
	_, err = d.DB.Exec(insertReport, usr.RepName, usr.RepDesc, usr.DailyRuntime, usr.Location, usr.Cid)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		fmt.Println(err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Report Added Successfully !", "Status Code": "200 "})
}

//----------------------- Report Email Configuration API's ------------------

//--------------- Get All Report Email Config API ------------------

func GetReportEmailConfig(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	selectAllReportEmailConfig := "SELECT * from report_email_config where isdeleted=0;"
	rows, err := d.DB.Query(selectAllReportEmailConfig)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
	}
	var list []map[string]interface{}
	i := 0
	for rows.Next() {
		i++
		var eid, isdeleted int
		var email, rep_name, daily_time string
		rows.Scan(&eid, &email, &rep_name, &daily_time, &isdeleted)
		temp := map[string]interface{}{
			"Report Name": rep_name, "Email": email, "Daily Time": daily_time,
		}
		list = append(list, temp)
	}
	if i == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Records Found", "Status Code": "202 "})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list})

}

//----------------- Get Report Email Config By Id API ------------------

func GetReportEmailConfigById(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	eid, _ := strconv.Atoi(vars["eid"])
	//selectReportEmailConfig := "SELECT * from report_email_config where eid=$1;"
	selectReportEmailConfig := fmt.Sprintf("SELECT * from report_email_config where eid=%d and isdeleted=0", eid)
	rows, err := d.DB.Query(selectReportEmailConfig)

	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
	}
	var temp m.AddReportEmailConfig
	i := 0
	for rows.Next() {
		var eid1, isdeleted int
		i++
		err = rows.Scan(&eid1, &temp.RepEmail, &temp.ReportName, &temp.DailyTime, &isdeleted)

	}
	if i == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Rows Returned", "Status Code": "202 "})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": temp})
}

//----------------- Add Report Email Config API ------------------

func AddReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var repemail m.AddReportEmailConfig
	err := json.NewDecoder(r.Body).Decode(&repemail)
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400 Bad Request", "Message": err})
		return
	}
	insertReportEmailConfig := "INSERT INTO report_email_config (email, rep_name, daily_time) VALUES($1,$2,$3)"
	_, err = d.DB.Exec(insertReportEmailConfig, repemail.RepEmail, repemail.ReportName, repemail.DailyTime)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		fmt.Println(err)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "success"})
}

//------------- Update Report Email Config By ID API ----------------

func UpdateReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	eid, _ := strconv.Atoi(vars["eid"])
	var repEmail m.AddReportEmailConfig

	err := json.NewDecoder(r.Body).Decode(&repEmail)
	if err != nil {
		log.Fatalln("There was an error decoding the request body into the struct")
	}

	//updateQuery := "UPDATE USERS SET first_name=$1 , last_name=$2, phno=$3, user_name=$4 where uid=$5"
	updateQuery := fmt.Sprintf("UPDATE report_email_config SET email='%s', rep_name='%s', daily_time='%s' where eid=%d", repEmail.RepEmail, repEmail.ReportName, repEmail.DailyTime, eid)
	fmt.Println(updateQuery)
	_, err = d.DB.Exec(updateQuery)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Record Updated Successfully !!!", "Status Code": "200 "})

}

//--------------- Delete Record Email Config By Id API -----------------

func DeleteReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	vars := mux.Vars(r)
	eid, _ := strconv.Atoi(vars["eid"])

	deleteUser := "Update report_email_config set isdeleted=1 where eid=$1;"
	_, err := d.DB.Exec(deleteUser, eid)
	//fmt.Println(company_id)

	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Deleted Successfully", "Status Code": "200 "})
}

// Change Password API

func ChangePass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var data m.ChangePassword
	var pass string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Fatalln("There was an error decoding the request body into the struct", err)
	}

	changePass := "SELECT password from USERS WHERE uid = $1"
	rows, err := d.DB.Query(changePass, data.Uid)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}
	for rows.Next() {
		rows.Scan(&pass)
	}
	pass2 := PasswordDecoder(pass)
	fmt.Println(data.Uid)
	fmt.Println(pass)
	fmt.Println(pass2)
	if pass2 != data.OldPass {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid Old Password", "Status Code": "202 "})
		return
	}
	EncPass := PasswordEncoder(data.NewPass)
	changePass2 := "UPDATE USERS SET PASSWORD=$1 WHERE UID=$2"
	_, err = d.DB.Exec(changePass2, EncPass, data.Uid)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Password Updated Successfully !!!", "Status Code": "202 "})
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
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
	}

	checkUser := "SELECT user_name, password from USERS where user_name = $1"
	rows, err := d.DB.Query(checkUser, usr.UserName)
	fmt.Println(usr.UserName)
	fmt.Println(usr.Password)
	var user_name, pwd string
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
	}
	for rows.Next() {
		rows.Scan(&user_name, &pwd)
	}
	DecPass := PasswordDecoder(pwd)
	fmt.Println(pwd)
	fmt.Println(DecPass)
	if user_name == usr.UserName && DecPass == usr.Password {
		//var role string
		returnUser := "SELECT users.uid ,users.first_name, users.last_name, users.user_name, users.cid, role.role_name FROM users JOIN users_role ON users.uid = users_role.uid JOIN role ON role.rid = users_role.rid where user_name=$1;"
		rows, err := d.DB.Query(returnUser, user_name)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		}
		for rows.Next() {

			rows.Scan(&usr.Uid, &usr.FirstName, &usr.LastName, &usr.UserName, &usr.Cid, &usr.Role)
		}

		var cname string
		companyName := "Select cname from company_details where cid=$1"
		rows, err = d.DB.Query(companyName, usr.Cid)
		//fmt.Println(usr.Cid)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
		}
		for rows.Next() {
			rows.Scan(&cname)
		}
		temp := map[string]interface{}{
			"uid": usr.Uid, "user_name": usr.UserName, "FirstName": usr.FirstName, "LastName": usr.LastName, "CompanyName": cname, "Role": usr.Role,
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200", "data": temp})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Wrong Password", "Status Code": "202 "})
}

// ------------------- Forgot Password API ------------------

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var usr m.Users_Role
	var email string
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
	}
	checkMail := "SELECT user_name from USERS WHERE user_name=$1;"

	rows, err := d.DB.Query(checkMail, usr.UserName)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
	}
	i := 0
	for rows.Next() {
		i++
		rows.Scan(&email)
	}
	// if i != 0 {

	// }
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
		log.Fatal(err)
	}
	fmt.Println(DecPass)
	return string(DecPass)
}
