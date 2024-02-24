package main

import "github.com/go-webauthn/webauthn/webauthn"

type User struct {
	ID          []byte
	DisplayName string
	Name        string

	creds []webauthn.Credential
}

func (o *User) WebAuthnID() []byte {
	return o.ID
}

func (o *User) WebAuthnName() string {
	return o.Name
}

func (o *User) WebAuthnDisplayName() string {
	return o.DisplayName
}

func (o *User) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (o *User) WebAuthnCredentials() []webauthn.Credential {
	return o.creds
}

func (o *User) AddCredential(credential *webauthn.Credential) {
	o.creds = append(o.creds, *credential)
}

func (o *User) UpdateCredential(credential *webauthn.Credential) {
	for i, c := range o.creds {
		if string(c.ID) == string(credential.ID) {
			o.creds[i] = *credential
		}
	}
}
