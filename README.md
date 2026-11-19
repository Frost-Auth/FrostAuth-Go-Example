# FrostAuth-Go-Example 🌟

Go example for the [FrostAuth license key API](https://www.frostauth.cc/).

`frostauth/frostauth.go` uses the Go standard library. Start with `example/main.go` to see the console flow.

## Bugs

If you can reproduce the issue with the example, open an issue with the SDK version, `go version`, and the exact error. Remove license keys and tokens before posting.

## Security practices

- Keep credentials, license keys, and session tokens out of logs.
- Handle errors by code. The API can change the message text.
- Keep authorization for server resources on the server.
- Run your usual signing and integrity checks before shipping.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing API with device-bound keys, app accounts, and a dashboard for managing licenses and tracking activations. SDKs are available for C++, C#, Go, Java, JavaScript, Python, and Rust. For product questions, join the [FrostAuth Discord](https://www.frostauth.cc/discord).

## Requirements

Go 1.24 or newer, as specified in `go.mod`.

## Build

Run these commands from the SDK directory after setting your product details in the example.

```bash
go build ./...          # compiles library + example
go vet ./...            # static checks, must be clean
go run ./example        # run the console example
go build -o frostauth-go.exe ./example   # standalone binary
```

## `FrostAuth` instance definition

Copy the owner ID and product ID from the FrostAuth dashboard into `example/main.go`. Set the version you plan to ship.

```go
app, err := frostauth.New(frostauth.Options{
    Owner:   "0809y7MP",                                  // dashboard → owner id
    Product: "33abf48a-8e33-4df5-a4bd-d79195704d52",      // dashboard → product → product id
    Version: "1.0.0",                                     // must match the version you ship
})
if err != nil {
    fail(err)
}
```

## Initialize application

Call `Init()` first. It fetches the public catalog, checks its signing key against the bundled pin, and uses that key to verify signed API responses.

```go
if _, err := app.Init(); err != nil {
    fail(err)
}
```

## Display application information

Call this after activation or sign-in has returned a session token.

```go
appData, err := app.AppData()
if err != nil {
    fail(err)
}
if product, ok := appData["product"].(map[string]any); ok {
    fmt.Println("App version:", product["version"])
}
```

## Check session validation

Use `Validate()` after activation or sign-in. If the API rejects a stale session token, the SDK retries once with the stored license key when it has one.

```go
if _, err := app.Validate(); err != nil {
    fail(err)
}
```

## Check blacklist status

Call this with an active session. The API also applies blacklist rules during activation and sign-in.

```go
if _, err := app.CheckBlacklist(); err != nil {
    fail(err)
}
```

## Login with username/password

Pass the account credentials and supply a two-factor code when the account requires one.

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

Apply the license key to the existing account, then sign in to open a session.

```go
if _, err := app.Upgrade(username, password, key); err != nil {
    fail(err)
}
fmt.Println("Upgraded. Sign in to use the new licence.")
snap, err := app.Login(username, password, map[string]string{})
```

## Login with just license key

For key-only products, activate with the license key. The API applies the product's device rules and issues a session token where supported.

```go
snap, err := app.Activate(key, map[string]string{})
if err != nil {
    fail(err)
}
```

For products that check builds, pass `map[string]string{"hash": selfHash}` and add a `label` entry if you want to name the device.

## User Data

`Snapshot()` reads the client state. The account and device fields depend on how the user activated or signed in.

```go
snap := app.Snapshot()
fmt.Println("Username:", snap.User)
fmt.Println("IP:", snap.Account["lastIp"])
fmt.Println("Device Id:", snap.Device["id"])
for i, s := range snap.Subs {
    fmt.Printf("[%d] Subscription: %v\n", i+1, s["tier"])
}
```

## Check subscription of user

Use the tier name you set in the dashboard. This example checks for `pro`.

```go
hasPro := false
for _, s := range snap.Subs {
    if tier, ok := s["tier"].(string); ok && strings.EqualFold(tier, "pro") {
        hasPro = true
    }
}
if !hasPro {
    fmt.Println("This feature needs a Pro subscription.")
    os.Exit(1)
}
```

## Application variables

Edit shared variables in the dashboard. The API applies the variable's tier and version rules when the SDK reads it.

```go
motd, err := app.Variable("maintenance_message")
if err != nil {
    fail(err)
}
fmt.Println("MOTD:", motd)
```

## User Variables

Use these calls for account-specific values. The API blocks client writes to variables marked read-only.

```go
vars, err := app.ListVars()
if err != nil {
    fail(err)
}
fmt.Println(vars)
theme, err := app.GetVar("theme")
if err != nil {
    fail(err)
}
fmt.Println("theme:", theme)
if _, err := app.SetVar("theme", "dark"); err != nil {
    fail(err)
}
```

## Application Logs

Call `Log()` to send an event to the operator. The product's logging settings determine where it appears.

```go
app.Log("client started, integrity check passed")
```

## Ban the user

`Ban()` requires an active session. It blacklists the device and IP address and ends the SDK's local session.

```go
app.Ban("debugger detected") // reason shows on next login + dashboard
```

## Server-side webhooks

Pass the ID of a webhook configured by the product operator. The destination stays on the server.

```go
res, err := app.Webhook("discord", "", `{"content":"Hello from FrostAuth"}`, "")
if err != nil {
    fail(err)
}
fmt.Println("upstream:", res["status"], "ok:", res["ok"])
```

## Heartbeat & offline

Start the heartbeat after activation or sign-in. `CheckOffline()` verifies the cached signed assertion, including its expiry.

If the assertion expires or fails verification during an outage, the next failed heartbeat clears the active state. An invalid API response signature also stops the heartbeat and clears the active state.

Set `Options.OfflineGraceSeconds` to change the 15-minute fallback for sessions that received no assertion.

```go
app.OnOffline = func(err *frostauth.Error, secondsOffline int, verified bool) {
    fmt.Println("offline:", secondsOffline, "verified:", verified)
}
if err := app.StartHeartbeat(0); err != nil {
    fail(err)
}
if ok, reason := app.CheckOffline(); !ok {
    fmt.Println("offline:", reason)
}
defer app.StopHeartbeat()
```

## Compatibility checks

From the Cerberus repository root on Linux, run `bash sdk/compatibility/run.sh go`. The suite uses a local API fixture to test activation, validation, signed errors, and offline heartbeat behavior.

This SDK initialized successfully against the live FrostAuth API on November 18, 2026. A live activation and heartbeat require a disposable license.

## SDK layout

- `frostauth/frostauth.go` contains the SDK.
- `example/main.go` runs the interactive example.
