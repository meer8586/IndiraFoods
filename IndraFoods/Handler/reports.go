package Handler

import (
	d "Foods/DB"
	m "Foods/Model"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

//---------------- Get All Reports API --------------

func GetAllReports(w http.ResponseWriter, r *http.Request) {
	var list []m.Reports
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
		page, _ := strconv.Atoi(vars["page"])
		limit, _ := strconv.Atoi(vars["limit"])
		if page < 1 {
			page = 1

		}
		if limit < 1 {
			limit = 10
		}
		offset := (page - 1) * limit

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

		count := 0
		selectCount := "SELECT COUNT(*) FROM Report where cid =$1;"
		rows2, err := d.DB.Query(selectCount, company_id)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		for rows2.Next() {
			rows2.Scan(&count)
		}

		//selectReports := "SELECT * from report where cid=$1;"
		selectReports := "Select repid, rep_name, rep_desc, location, cid, created_at, daily_runtime from report where cid=$1 limit $2 offset $3;"
		rows1, err := d.DB.Query(selectReports, company_id, limit, offset)
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
		totalPage := math.Ceil(float64(count) / float64(limit))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list, "pageNo": page, "limit": limit, "totalItems": count, "totalPage": totalPage})
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		fmt.Println(tokenString)
		var list []m.Reports
		company_id, _ := strconv.Atoi(vars["cid"])
		repname := vars["repname"]
		page, _ := strconv.Atoi(vars["page"])
		limit, _ := strconv.Atoi(vars["limit"])
		if page < 1 {
			page = 1

		}
		if limit < 1 {
			limit = 10
		}
		offset := (page - 1) * limit
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

		count := 0
		selectCount := "SELECT COUNT(*) FROM Report where cid =$1 and rep_name=$2;"
		rows2, err := d.DB.Query(selectCount, company_id, repname)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error()})
			Logger.Print(err.Error())
			return
		}
		for rows2.Next() {
			rows2.Scan(&count)
		}

		selectReports := "SELECT repid, rep_name, rep_desc, location, cid, created_at, daily_runtime from report where cid = $1 and rep_name=$2 order by created_at desc limit $3 offset $4;"
		rows1, err := d.DB.Query(selectReports, company_id, repname, limit, offset)
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
		totalPage := math.Ceil(float64(count) / float64(limit))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "success", "Status Code": "200 ", "data": list, "pageNo": page, "limit": limit, "totalItems": count, "totalPage": totalPage})
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

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Added " + usr.RepName + " In Report Table"
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

// ------------------------ Download Report API -----------------------

func DownloadReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
		//var downloadreport m.DownloadReport
		vars := mux.Vars(r)
		repid, err := strconv.Atoi(vars["repid"])
		var repname, location string
		var cid int
		//err := json.NewDecoder(r.Body).Decode(&downloadreport)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err.Error(), "Status Code": "202 "})
			fmt.Println(err)
			Logger.Print(err.Error())
			return
		}

		selectReport := "SELECT rep_name, location, cid FROM REPORT WHERE repid=$1 "
		rows, err := d.DB.Query(selectReport, repid)
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
			rows.Scan(&repname, &location, &cid)
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

		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " DownLoaded " + repname + " From Report Table"
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "DOWNLOAD", desc, cid)
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

//------------------- Store Report API -------------------

func StoreReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
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
		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Added " + sf.FileName
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
