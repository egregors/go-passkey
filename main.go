package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
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
	GetSession(token string) webauthn.SessionData
	SaveSession(token string, data webauthn.SessionData)
	DeleteSession(token string)
}

func main() {
	l = log.Default()

	proto := getEnv("PROTO", "http")
	host := getEnv("HOST", "localhost")
	port := getEnv("PORT", ":8080")
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	l.Printf("[INFO] make webauthn config")
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",    // Display Name for your site
		RPID:          host,             // Generally the FQDN for your site
		RPOrigins:     []string{origin}, // The origin URLs allowed for WebAuthn
	}

	l.Printf("[INFO] create webauthn")
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	l.Printf("[INFO] create datastore")
	datastore = NewInMem(l)

	l.Printf("[INFO] register routes")
	// Serve the web files
	http.Handle("/", http.FileServer(http.Dir("./web")))

	// Add auth the routes
	http.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	http.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	http.HandleFunc("/api/passkey/loginStart", BeginLogin)
	http.HandleFunc("/api/passkey/loginFinish", FinishLogin)

	// Start the server
	l.Printf("[INFO] start server at %s", origin)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println(err)
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	l.Printf("[INFO] begin registration ----------------------\\")

	username, err := getUsername(r)
	if err != nil {
		l.Printf("[ERRO] can't get user name: %s", err.Error())
		panic(err)
	}

	user := datastore.GetUser(username) // Find or create the new user

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		JSONResponse(w, "", msg, http.StatusBadRequest)

		return
	}

	// Make a session key and store the sessionData values
	t := uuid.New().String()
	datastore.SaveSession(t, *session)

	JSONResponse(w, t, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// Get the session key from the header
	t := r.Header.Get("Session-Key")
	// Get the session data stored from the function above
	session := datastore.GetSession(t) // FIXME: cover invalid session

	// In out example username == userID, but in real world it should be different
	user := datastore.GetUser(string(session.UserID)) // Get the user

	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		JSONResponse(w, "", msg, http.StatusBadRequest)

		return
	}

	// If creation was successful, store the credential object
	user.AddCredential(credential)
	datastore.SaveUser(user)
	// Delete the session data
	datastore.DeleteSession(t)

	l.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, "", "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	l.Printf("[INFO] begin login ----------------------\\")

	username, err := getUsername(r)
	if err != nil {
		l.Printf("[ERRO]can't get user name: %s", err.Error())
		panic(err)
	}

	user := datastore.GetUser(username) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		l.Printf("[ERRO] %s", msg)
		JSONResponse(w, "", msg, http.StatusBadRequest)

		return
	}

	// Make a session key and store the sessionData values
	t := uuid.New().String()
	datastore.SaveSession(t, *session)

	JSONResponse(w, t, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session key from the header
	t := r.Header.Get("Session-Key")
	// Get the session data stored from the function above
	session := datastore.GetSession(t) // FIXME: cover invalid session

	// In out example username == userID, but in real world it should be different
	user := datastore.GetUser(string(session.UserID)) // Get the user

	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		l.Printf("[ERRO] can't finish login %s", err.Error())
		panic(err)
	}

	// Handle credential.Authenticator.CloneWarning
	if credential.Authenticator.CloneWarning {
		l.Printf("[WARN] can't finish login: %s", "CloneWarning")
	}

	// If login was successful, update the credential object
	user.UpdateCredential(credential)
	datastore.SaveUser(user)
	// Delete the session data
	datastore.DeleteSession(t)

	l.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "", "Login Success", http.StatusOK)
}

// JSONResponse is a helper function to send json response
func JSONResponse(w http.ResponseWriter, sessionKey string, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Session-Key", sessionKey)
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

// getEnv is a helper function to get the environment variable
func getEnv(key, def string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return def
}
