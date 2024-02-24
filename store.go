package main

import "github.com/duo-labs/webauthn/webauthn"

type InMem struct {
	users    map[string]PasskeyUser
	sessions map[string]webauthn.SessionData

	log Logger
}

func NewInMem(log Logger) *InMem {
	return &InMem{
		users:    make(map[string]PasskeyUser),
		sessions: make(map[string]webauthn.SessionData),
		log:      log,
	}
}

func (i *InMem) GetSession(token string) webauthn.SessionData {
	i.log.Printf("[DEBUG] GetSession: %v", i.sessions[token])
	return i.sessions[token]
}

func (i *InMem) SaveSession(token string, data webauthn.SessionData) {
	i.log.Printf("[DEBUG] SaveSession: %s - %v", token, data)
	i.sessions[token] = data
}

func (i *InMem) DeleteSession(token string) {
	i.log.Printf("[DEBUG] DeleteSession: %v", token)
	delete(i.sessions, token)
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
