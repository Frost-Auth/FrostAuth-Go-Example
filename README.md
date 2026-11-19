# FrostAuth-Go-Example 🌟

FrostAuth Go example SDK for https://www.frostauth.cc license key API auth.

This example vendors the SDK source directly — `frostauth/frostauth.go`.
Import it, mirror `example/main.go`, and you're integrated. Zero third-party
modules, stdlib only.

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, Go version, and the exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
build steps below don't make sense yet, learn some Go first (Go tour/YouTube),
then come back.

## Security practices

* Ship releases through an obfuscator/protector (garble, VMProtect for cgo
builds) and put license checks behind their markers, not just `main()`.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call — don't add a local `isValid` boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for Go (this
repo), C++, C#, Python, Rust, Java, and JavaScript. Come ask questions on
Discord: https://www.frostauth.cc/discord

## Requirements

* Go 1.22+ (`go.mod` included, zero third-party modules)

## Build

```bash
cd FrostAuth-Go-Example
go build ./...          # compiles library + example
go vet ./...            # static checks, must be clean
go run ./example        # run the console example
go build -o frostauth-go.exe ./example   # standalone binary
```

## `FrostAuth` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`example/main.go`](example/main.go):

```go
app, err := frostauth.New(frostauth.Options{
    Owner:   "YOUR-OWNER-ID",     // dashboard → product → owner id
    Product: "YOUR-PRODUCT-ID",   // dashboard → product → product id
    Version: "1.0.0",             // must match the version you ship
})
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```go
if _, err := app.Init(); err != nil {
    fail(err)
}
```

## Display application information

```go
appData, _ := app.AppData()
if p, ok := appData["product"].(map[string]any); ok {
    fmt.Println("App Version:", p["version"])
    fmt.Println("Customer panel: enabled")
}
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```go
if _, err := app.Validate(); err != nil {
    fail(err) // session dead — exit, don't continue into paid code
}
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```go
if _, err := app.CheckBlacklist(); err != nil {
    fail(err) // blocked — exit
}
```

## Login with username/password

```go
snap, err := app.Login(username, password, map[string]string{})
if err != nil {
    fail(err)
}
```

## Register with username/password/key

```go
snap, err := app.Register(key, username, password, map[string]string{})
if err != nil {
    fail(err)
}
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```go
if _, err := app.Upgrade(username, password, key); err != nil {
    fail(err)
}
fmt.Println("Upgraded. Sign in to use the new licence.")
snap, err := app.Login(username, password, map[string]string{})
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```go
snap, err := app.Activate(key, map[string]string{})
if err != nil {
    fail(err)
}
```

Extra build evidence: pass `map[string]string{"hash": selfHash}` (with an
optional `"label"`) when the product has hash checks on.

## User Data

Everything about the current session lives in the snapshot:

```go
snap, _ := app.Session()
fmt.Println("Username:", snap.User)
fmt.Println("IP:", snap.Account["lastIp"])
fmt.Println("Device Id:", snap.Device["id"])
for i, s := range snap.Subs {
    fmt.Printf("[%d] Subscription: %v\n", i+1, s["tier"])
}
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```go
hasPro := false
for _, s := range snap.Subs {
    if tier, _ := strings.ToLower(s["tier"].(string)); tier == "pro" {
        hasPro = true
    }
}
if !hasPro {
    fmt.Println("This feature needs a Pro subscription.")
    os.Exit(1)
}
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```go
motd, err := app.Variable("maintenance_message")
fmt.Println("MOTD:", motd)
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```go
vars, _ := app.ListVars()              // every variable on this user
theme, _ := app.GetVar("theme")        // one variable's value
app.SetVar("theme", "dark")            // write it back
fmt.Println("theme:", theme)
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```go
app.Log("client started, integrity check passed")
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```go
app.Ban("debugger detected") // reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```go
res, err := app.Webhook("discord", "", `{"content":"Hello from FrostAuth"}`, "")
fmt.Println("upstream:", res["status"], "ok:", res["ok"])
```

## Download file

> Currently disabled server-side (route unmounted). `File()` returns a
> `CodeServerError` until file storage ships. The snippet below is the
> integration pattern for when it lands.

```go
bytes, err := app.File("loader")
if err != nil {
    fail(err)
}
os.WriteFile("loader.bin", bytes, 0600)
```

## Changing username

Lets a signed-in user rename themselves (password re-checked server-side).

```go
res, err := app.ChangeUsername(newName, password)
fmt.Println("Renamed to", res["username"])
```

## Heartbeat & offline

`Validate()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion — when the network drops, `CheckOffline()` verifies it
locally so the app keeps working inside the grace window.

```go
app.OnOffline = func(err *frostauth.Error, secondsOffline int, verified bool) {
    fmt.Println("offline:", secondsOffline, "verified:", verified)
}
app.StartHeartbeat(0) // server cadence until Stop/Close
defer app.StopHeartbeat()
```

## SDK layout

* `frostauth/frostauth.go` — the whole SDK. Import `github.com/frostauth/sdk-go/frostauth`.
* `example/main.go` — the interactive demo this README walks through.
