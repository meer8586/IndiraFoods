package Handler

import (
	d "Foods/DB"
	m "Foods/Model"
	"encoding/json"
	"fmt"
	"net/http"
)

//-----------------------------Add Company API--------------------------------------

func AddCompany(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST,PUT,DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	isValidToken, tokenString := VerifyToken(w, r)
	fmt.Println(isValidToken)
	if isValidToken {
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
		userName, er := extractUserNameFromToken(tokenString)
		if er != nil {
			Logger.Print(er.Error())
		}

		desc := userName + " Added " + cmp.Cname
		insertAudit := "INSERT INTO AUDIT_LOG (action_done_by, action, action_desc, cid) VALUES($1, $2, $3, $4);"
		_, err = d.DB.Exec(insertAudit, userName, "INSERT", desc, 29)
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
