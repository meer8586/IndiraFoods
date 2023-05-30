package Routes

import (
	"log"
	"net/http"

	c "Foods/Controllers"

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
	myRouter.HandleFunc("/login", c.Login).Methods("POST")

	myRouter.HandleFunc("/addcomp", c.AddCompany).Methods("POST")

	myRouter.HandleFunc("/allusers/{cid}", c.GetAllUsers).Methods("GET")
	myRouter.HandleFunc("/getuserbyid/{uid}", c.GetUser).Methods("GET")
	myRouter.HandleFunc("/adduser", c.AddUser).Methods("POST")
	myRouter.HandleFunc("/deleteuser/{uid}", c.DeleteUser).Methods("DELETE")
	myRouter.HandleFunc("/updateuser/{uid}", c.UpdateUser).Methods("PUT")

	myRouter.HandleFunc("/getreports/{cid}", c.GetAllReports).Methods("GET")
	myRouter.HandleFunc("/getreport/{cid}/{repname}", c.GetReport).Methods("GET")
	myRouter.HandleFunc("/addreport", c.AddReport).Methods("POST")
	myRouter.HandleFunc("/savereport/{cid}", c.StoreReport).Methods("POST")
	myRouter.HandleFunc("/downloadreport", c.DownloadReport).Methods("POST")

	myRouter.HandleFunc("/getrepemailconfig/{cid}", c.GetReportEmailConfig).Methods("GET")
	myRouter.HandleFunc("/getrepemailconfigbyid/{eid}", c.GetReportEmailConfigById).Methods("GET")
	myRouter.HandleFunc("/addrepemailconfig/{cid}", c.AddReportEmailConfig).Methods("POST")
	myRouter.HandleFunc("/updaterepemailconfig/{eid}", c.UpdateReportEmailConfig).Methods("PUT")
	myRouter.HandleFunc("/deleterepemailconfig/{eid}", c.DeleteReportEmailConfig).Methods("DELETE")

	myRouter.HandleFunc("/changepass", c.ChangePass).Methods("PUT")

	myRouter.HandleFunc("/forgotpassword", c.ForgotPassword).Methods("POST")
	myRouter.HandleFunc("/verifyotp", c.VerifyOTP).Methods("POST")
	myRouter.HandleFunc("/resetpass", c.ResetPass).Methods("PUT")

	corsRouter := corsMiddleware(myRouter)
	log.Fatal(http.ListenAndServe(":8082", corsRouter))

}
