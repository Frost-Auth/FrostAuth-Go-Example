package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	frostauth "github.com/frostauth/sdk-go/frostauth"
)

func fail(err error) {
	if fe, ok := err.(*frostauth.Error); ok {
		fmt.Printf("An error occurred: %s\n", fe.Error())
	} else if err != nil {
		fmt.Println("An error occurred:", err)
	} else {
		fmt.Println("An unknown error occurred")
	}
	os.Exit(1)
}

func main() {
	app, err := frostauth.New(frostauth.Options{
		Owner:   "0809wkVP",
		Product: "33abf48a-8e33-4df5-a4bd-d79195704d52",
		Version: "1.0.0",
	})
	if err != nil {
		fail(err)
	}
	if _, err := app.Init(); err != nil {
		fail(err)
	}

	reader := bufio.NewReader(os.Stdin)
	ask := func(q string) string {
		fmt.Print(q)
		s, _ := reader.ReadString('\n')
		return strings.TrimSpace(s)
	}

	fmt.Println("[1] Login\n[2] Register\n[3] License\n[4] Upgrade")
	option := ask("Select an option: ")

	switch option {
	case "1":
		_, err = app.Login(ask("Username: "), ask("Password: "), nil)
	case "2":
		_, err = app.Register(ask("License: "), ask("Username: "), ask("Password: "), nil)
	case "3":
		_, err = app.Activate(ask("License: "), nil)
	case "4":
		username := ask("Username: ")
		password := ask("Password: ")
		license := ask("License: ")
		if _, err = app.Upgrade(username, password, license); err == nil {
			fmt.Println("Upgraded. Sign in to use the new licence.")
			_, err = app.Login(username, password, nil)
		}
	default:
		fmt.Println("Invalid option selected.")
		return
	}
	if err != nil {
		fail(err)
	}

	dashboard(app)
}

func showUser(snap frostauth.Snapshot) {
	when := func(iso string) string {
		if iso == "" {
			return "—"
		}
		if t, perr := time.Parse(time.RFC3339, iso); perr == nil {
			return t.Format("1/2/2006, 3:04:05 PM")
		}
		return "—"
	}
	strOf := func(m map[string]any, key string) string {
		if m == nil {
			return ""
		}
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}

	who := snap.User
	if who == "" {
		who = strOf(snap.Account, "username")
	}
	if who == "" {
		who = "unknown"
	}
	tier := strOf(snap.License, "tier")
	if tier == "" {
		tier = "starter"
	}
	state := strOf(snap.License, "status")
	if state == "" {
		state = "unknown"
	}

	expiry := strOf(snap.License, "expiresAt")
	if expiry == "" {
		for _, raw := range snap.Subscriptions {
			if sub, ok := raw.(map[string]any); ok {
				if iso, ok := sub["expiresAt"].(string); ok && iso != "" {
					expiry = iso
					break
				}
			}
		}
	}
	validLine := "never"
	if expiry != "" {
		validLine = when(expiry)
		if t, perr := time.Parse(time.RFC3339, expiry); perr == nil {
			diff := t.Sub(time.Now())
			days := 0
			if diff > 0 {
				days = int((diff + (24*time.Hour - time.Second)) / (24 * time.Hour))
			}
			validLine = fmt.Sprintf("%s (%dd left)", validLine, days)
		}
	}

	prodName := strOf(snap.Product, "name")
	if prodName == "" {
		prodName = "—"
	}
	prodLine := prodName
	if v := strOf(snap.Product, "version"); v != "" {
		prodLine += " v" + v
	}

	used := "—"
	if v, ok := snap.License["devicesUsed"]; ok && v != nil {
		used = fmt.Sprintf("%v", v)
	}
	devicesLine := used
	if b, _ := snap.License["unlimitedDevices"].(bool); b {
		devicesLine = used + " (unlimited)"
	} else if lim, ok := snap.License["deviceLimit"]; ok && lim != nil {
		devicesLine = fmt.Sprintf("%s / %v", used, lim)
	}

	devLine := strOf(snap.Device, "id")
	if devLine == "" {
		devLine = "—"
	}

	ipLine := strOf(snap.Account, "lastIp")
	if ipLine == "" {
		ipLine = "—"
	}

	fmt.Println("")
	fmt.Printf("Signed in as %s\n", who)
	fmt.Println("----------------------------------------------")
	fmt.Printf("  Licence ..... %s (%s)\n", state, tier)
	fmt.Printf("  IP Address .. %s\n", ipLine)
	fmt.Printf("  Product ..... %s\n", prodLine)
	fmt.Printf("  Devices ..... %s\n", devicesLine)
	fmt.Printf("  Valid Until . %s\n", validLine)
	fmt.Printf("  Device Id ... %s\n", devLine)
	fmt.Printf("  First Seen .. %s\n", when(strOf(snap.Account, "createdAt")))
	fmt.Printf("  Last Seen ... %s\n", when(strOf(snap.Account, "lastLoginAt")))
	fmt.Println("----------------------------------------------")
}

func dashboard(app *frostauth.FrostAuth) {
	loc := func(iso string) string {
		t, perr := time.Parse(time.RFC3339, iso)
		if perr != nil || iso == "" {
			return "unknown"
		}
		return t.Format("1/2/2006, 3:04:05 PM")
	}

	snap := app.Snapshot()

	showUser(snap)

	subs := snap.Subscriptions
	for i, raw := range subs {
		sub, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := sub["tier"].(string)
		if name == "" {
			name, _ = sub["status"].(string)
		}
		expiry := "never"
		if iso, ok := sub["expiresAt"].(string); ok && iso != "" {
			expiry = loc(iso)
		}
		fmt.Printf("[%d/%d] | Subscription: %s - Expiry: %s\n", i+1, len(subs), name, expiry)
	}

	createdAt := "unknown"
	if iso, ok := snap.Account["createdAt"].(string); ok && iso != "" {
		createdAt = loc(iso)
	}
	fmt.Println("Created at:", createdAt)
	lastLogin := "unknown"
	if iso, ok := snap.Account["lastLoginAt"].(string); ok && iso != "" {
		lastLogin = loc(iso)
	}
	fmt.Println("Last Login:", lastLogin)
	expires := "never"
	for _, raw := range subs {
		sub, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if iso, ok := sub["expiresAt"].(string); ok && iso != "" {
			expires = loc(iso)
			break
		}
	}
	fmt.Println("Expires:", expires)

	if res, err := app.Webhook("discord", "", `{"content":"Hello from FrostAuth"}`, ""); err == nil {
		status, ok := res["status"].(float64)
		rok, _ := res["ok"].(bool)
		if ok && rok {
			fmt.Printf("\nWebhook test: upstream %d (ok: %v)\n", int(status), rok)
		} else {
			fmt.Println("\nWebhook test failed: unexpected response shape")
		}
	} else if fe, ok := err.(*frostauth.Error); ok {
		fmt.Printf("\nWebhook test failed: %s %s\n", fe.Code, fe.Error())
	} else {
		fmt.Printf("\nWebhook test failed: %s\n", err)
	}

	self := "unavailable"
	if p, e := os.Executable(); e == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			sum := sha256.Sum256(data)
			self = hex.EncodeToString(sum[:])
		}
	}
	fmt.Println("\nBuild hash (this file):")
	fmt.Println("  " + self)
	fmt.Println("  Pass it as map[string]string{\"hash\": self} to activate/register/login when the product requires it.")

	fmt.Println("\nClosing app in 10 seconds...")
	time.Sleep(10 * time.Second)
	_, _ = app.Logout()
}
