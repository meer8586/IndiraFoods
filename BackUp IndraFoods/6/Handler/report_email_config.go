package Handler

import (
	d "Foods/DB"
	m "Foods/Model"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// -------------- Get All Report Email Config API -----------------

func GetReportEmailConfig(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Added " + repemail.RepEmail + " And " + repemail.ReportName + " In Report Email Config Table"
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "INSERT", desc, company_id)
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

//------------- Update Report Email Config By ID API ----------------

func UpdateReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

		var cid int
		selectCid := "select cid from users where eid =$1;"
		rows, err := d.DB.Query(selectCid, eid)
		for rows.Next() {
			rows.Scan(&cid)
		}
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
		}
		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Updated Report Email Config Table"
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

//--------------- Delete Record Email Config By Id API -----------------

func DeleteReportEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		vars := mux.Vars(r)
		eid, _ := strconv.Atoi(vars["eid"])
		var cid int
		var email string
		seletQuery := "select eid ,email, cid from report_email_config where eid = $1 and isdeleted=0;"
		rows, _ := d.DB.Query(seletQuery, eid)
		i := 0

		defer rows.Close()
		for rows.Next() {
			i++
			rows.Scan(&eid, &email, &cid)
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Deleted " + email + " From Report Email Config Table"
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
