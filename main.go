package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error

	datastore PasskeyStore
	l         Logger
)

type Logger interface {
	Printf(format string, v ...interface{})
}

type PasskeyUser interface {
	webauthn.User
	AddCredential(*webauthn.Credential)
	UpdateCredential(*webauthn.Credential)
}

type PasskeyStore interface {
	GetUser(userName string) PasskeyUser
	SaveUser(PasskeyUser)
	GetSession() webauthn.SessionData
	SaveSession(webauthn.SessionData)
}

func main() {
	l = log.Default()

	l.Printf("[INFO] make webauthn config")
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",      // Display Name for your site
		RPID:          "localhost",        // Generally the FQDN for your site
		RPOrigin:      "http://localhost", // The origin URLs allowed for WebAuthn requests
	}

	l.Printf("[INFO] create webauthn")
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
	}

	l.Printf("[INFO] create datastore")
	datastore = NewInMem(l)

	l.Printf("[INFO] register routes")
	// add index
	http.Handle("/", http.FileServer(http.Dir("./web")))

	// add auth the routes
	http.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	http.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	http.HandleFunc("/api/passkey/loginStart", BeginLogin)
	http.HandleFunc("/api/passkey/loginFinish", FinishLogin)

	// add the static files
	http.Handle("/static", http.FileServer(http.Dir("./static")))

	// start the server
	l.Printf("[INFO] start server at http://localhost:80/")
	if err := http.ListenAndServe(":80", nil); err != nil {
		fmt.Println(err)
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username, err := getUsername(r)
	if err != nil {
		panic(err)
	}

	user := datastore.GetUser(username) // Find or create the new user
	options, session, err := webAuthn.BeginRegistration(user)
	// handle errors if present
	if err != nil {
		panic(err)
	}
	// store the sessionData values
	datastore.SaveSession(*session)

	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// Get the session data stored from the function above
	session := datastore.GetSession()

	// FIXME: in out example username == userID, but in real world it should be different
	user := datastore.GetUser(string(session.UserID)) // Get the user

	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		panic(err)
	}

	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.
	user.AddCredential(credential)
	datastore.SaveUser(user)

	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	username, err := getUsername(r)
	if err != nil {
		panic(err)
	}

	user := datastore.GetUser(username) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		panic(err)
	}

	// store the session values
	datastore.SaveSession(*session)

	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session data stored from the function above
	session := datastore.GetSession()

	// FIXME: in out example username == userID, but in real world it should be different
	user := datastore.GetUser(string(session.UserID)) // Get the user

	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		panic(err)
	}

	// Handle credential.Authenticator.CloneWarning

	// If login was successful, update the credential object
	// Pseudocode to update the user credential.
	user.UpdateCredential(credential)
	datastore.SaveUser(user)

	JSONResponse(w, "Login Success", http.StatusOK)
}

func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// getUsername is a helper function to extract the username from json request
func getUsername(r *http.Request) (string, error) {
	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Username, nil
}
