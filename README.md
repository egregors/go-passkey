# Go WebAuthn/Passkey Example

This is a simple example of WebAuthn and Passkey authentication using Go and JavaScript
from my blog post [PassKey in Go](https://dev.to/egregors/passkey-in-go-1efk).

> [!IMPORTANT]  
> I created a simple library based on this demonstration. It allows you to quickly and easily add Passkey support to your Golang application.
> The library includes fixes for errors made in this tutorial.
> [Check this out!](https://github.com/egregors/passkey)

## Demo

https://github.com/egregors/go-passkey/assets/2153895/6daeb93f-2dbb-467f-821e-8d1135090883

### Run by yourself

Set host and port by ENV vars `PROTO`, `HOST` and `PORT` or use default `http://localhost:8080`

Run server: `go run .`

## References

* Go WebAuthn lib: https://github.com/go-webauthn/webauthn
* JS lib to use WebAuthn browser API: https://simplewebauthn.dev/docs/packages/browser
* Node + Passkey tutorial https://www.corbado.com/blog/passkey-tutorial-how-to-implement-passkeys 
