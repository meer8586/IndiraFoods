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
	//handler := cors.Default().Handler(myRouter)

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

	myRouter.HandleFunc("/getrepemailconfig", c.GetReportEmailConfig).Methods("GET")
	myRouter.HandleFunc("/getrepemailconfigbyid/{eid}", c.GetReportEmailConfigById).Methods("GET")
	myRouter.HandleFunc("/addrepemailconfig", c.AddReportEmailConfig).Methods("POST")
	myRouter.HandleFunc("/updaterepemailconfig/{eid}", c.UpdateReportEmailConfig).Methods("PUT")
	myRouter.HandleFunc("/deleterepemailconfig/{eid}", c.DeleteReportEmailConfig).Methods("DELETE")

	myRouter.HandleFunc("/changepass", c.ChangePass).Methods("PUT")

	myRouter.HandleFunc("/forgotpassword", c.ForgotPassword).Methods("POST")
	myRouter.HandleFunc("/verifyotp", c.VerifyOTP).Methods("POST")
	myRouter.HandleFunc("/resetpass", c.ResetPass).Methods("PUT")

	//handler := cors.Default().Handler(myRouter)

	// corsMiddleware := func(next http.Handler) http.Handler {
	// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		w.Header().Set("Access-Control-Allow-Origin", "*")
	// 		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	// 		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// 		if r.Method == "OPTIONS" {
	// 			w.WriteHeader(http.StatusOK)
	// 			return
	// 		}

	// 		next.ServeHTTP(w, r)
	// 	})
	// }

	// // Apply CORS middleware to all routes
	// myRouter.Use(corsMiddleware)
	corsRouter := corsMiddleware(myRouter)
	log.Fatal(http.ListenAndServe(":8081", corsRouter))

}
