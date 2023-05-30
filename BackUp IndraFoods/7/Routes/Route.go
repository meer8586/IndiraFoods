package Routes

import (
	"log"
	"net/http"

	h "Foods/Handler"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func WebService() {
	myRouter := mux.NewRouter().StrictSlash(true)

	// Define allowed origins. "*" allows requests from any origin.
	allowedOrigins := handlers.AllowedOrigins([]string{"*"})

	// Define allowed HTTP methods.
	allowedMethods := handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS", "PUT", "DELETE"})

	allowedHeaders := handlers.AllowedHeaders([]string{"Content-Type", "Authorization"})

	// Create the CORS middleware.
	corsMiddleware := handlers.CORS(allowedOrigins, allowedMethods, allowedHeaders)
	myRouter.HandleFunc("/login", h.Login).Methods("POST")

	myRouter.HandleFunc("/addcomp", h.AddCompany).Methods("POST")

	myRouter.HandleFunc("/allusers/{cid}/{page}/{limit}", h.GetAllUsers).Methods("GET")
	myRouter.HandleFunc("/getuserbyid/{uid}", h.GetUser).Methods("GET")
	myRouter.HandleFunc("/adduser", h.AddUser).Methods("POST")
	myRouter.HandleFunc("/deleteuser/{uid}", h.DeleteUser).Methods("DELETE")
	myRouter.HandleFunc("/updateuser/{uid}", h.UpdateUser).Methods("PUT")

	myRouter.HandleFunc("/getreports/{cid}/{page}/{limit}", h.GetAllReports).Methods("GET")
	myRouter.HandleFunc("/getreport/{cid}/{repname}/{page}/{limit}", h.GetReport).Methods("GET")
	myRouter.HandleFunc("/addreport", h.AddReport).Methods("POST")
	myRouter.HandleFunc("/savereport/{cid}", h.StoreReport).Methods("POST")
	myRouter.HandleFunc("/downloadreport/{repid}", h.DownloadReport).Methods("GET")

	myRouter.HandleFunc("/getrepemailconfig/{cid}/{page}/{limit}", h.GetReportEmailConfig).Methods("GET")
	myRouter.HandleFunc("/getrepemailconfigbyid/{eid}", h.GetReportEmailConfigById).Methods("GET")
	myRouter.HandleFunc("/addrepemailconfig/{cid}", h.AddReportEmailConfig).Methods("POST")
	myRouter.HandleFunc("/updaterepemailconfig/{eid}", h.UpdateReportEmailConfig).Methods("PUT")
	myRouter.HandleFunc("/deleterepemailconfig/{eid}", h.DeleteReportEmailConfig).Methods("DELETE")

	myRouter.HandleFunc("/changepass", h.ChangePass).Methods("PUT")

	myRouter.HandleFunc("/forgotpassword", h.ForgotPassword).Methods("POST")
	myRouter.HandleFunc("/verifyotp", h.VerifyOTP).Methods("POST")
	myRouter.HandleFunc("/resetpass", h.ResetPass).Methods("PUT")

	corsRouter := corsMiddleware(myRouter)
	log.Fatal(http.ListenAndServe(":8083", corsRouter))

}
