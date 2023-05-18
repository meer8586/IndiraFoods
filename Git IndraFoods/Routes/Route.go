package Routes

import (
	"log"
	"net/http"

	c "Foods/Controllers"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func WebService() {
	myRouter := mux.NewRouter().StrictSlash(true)

	myRouter.HandleFunc("/login", c.Login).Methods("POST")

	myRouter.HandleFunc("/addcomp", c.AddCompany).Methods("POST")

	myRouter.HandleFunc("/allusers", c.GetAllUsers).Methods("GET")
	myRouter.HandleFunc("/getuserbyid/{uid}", c.GetUser).Methods("GET")
	myRouter.HandleFunc("/adduser", c.AddUser).Methods("POST")
	myRouter.HandleFunc("/deleteuser/{uid}", c.DeleteUser).Methods("DELETE")
	myRouter.HandleFunc("/updateuser/{uid}", c.UpdateUser).Methods("PUT")

	myRouter.HandleFunc("/getreports/{cid}", c.GetAllReports).Methods("GET")
	myRouter.HandleFunc("/getreport/{cid}/{repname}", c.GetReport).Methods("GET")
	myRouter.HandleFunc("/addreport", c.AddReport).Methods("POST")
	myRouter.HandleFunc("/savereport/{cid}", c.StoreReport).Methods("POST")

	myRouter.HandleFunc("/getrepemailconfig", c.GetReportEmailConfig).Methods("GET")
	myRouter.HandleFunc("/getrepemailconfigbyid/{eid}", c.GetReportEmailConfigById).Methods("GET")
	myRouter.HandleFunc("/addrepemailconfig", c.AddReportEmailConfig).Methods("POST")
	myRouter.HandleFunc("/updaterepemailconfig/{eid}", c.UpdateReportEmailConfig).Methods("PUT")
	myRouter.HandleFunc("/deleterepemailconfig/{eid}", c.DeleteReportEmailConfig).Methods("DELETE")

	myRouter.HandleFunc("/changepass", c.ChangePass).Methods("PUT")

	myRouter.HandleFunc("/forgotpassword", c.ForgotPassword).Methods("POST")
	myRouter.HandleFunc("/verifyotp", c.VerifyOTP).Methods("POST")
	myRouter.HandleFunc("/resetpass", c.ResetPass).Methods("PUT")

	handler := cors.Default().Handler(myRouter)
	log.Fatal(http.ListenAndServe(":8081", handler))

}
