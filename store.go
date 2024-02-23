package main

import "github.com/duo-labs/webauthn/webauthn"

type InMem struct {
	users   map[string]PasskeyUser
	session webauthn.SessionData

	log Logger
}

func NewInMem(log Logger) *InMem {
	return &InMem{
		users: make(map[string]PasskeyUser),
		log:   log,
	}
}

func (i *InMem) GetSession() webauthn.SessionData {
	i.log.Printf("[DEBUG] GetSession: %v", i.session)
	return i.session
}

func (i *InMem) SaveSession(data webauthn.SessionData) {
	i.log.Printf("[DEBUG] SaveSession: %v", data)
	i.session = data
}

func (i *InMem) GetUser(userName string) PasskeyUser {
	i.log.Printf("[DEBUG] GetUser: %v", userName)
	if _, ok := i.users[userName]; !ok {
		i.log.Printf("[DEBUG] GetUser: creating new user: %v", userName)
		i.users[userName] = &User{
			ID:          []byte(userName),
			DisplayName: userName,
			Name:        userName,
		}
	}

	return i.users[userName]
}

func (i *InMem) SaveUser(user PasskeyUser) {
	i.log.Printf("[DEBUG] SaveUser: %v", user.WebAuthnName())
	i.log.Printf("[DEBUG] SaveUser: %v", user)
	i.users[user.WebAuthnName()] = user
}
