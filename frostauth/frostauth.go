package frostauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SDKVersion     = "1.0.0"
	DefaultBaseURL = "https://api.frostauth.cc"
	maxSkewMS      = 60_000
	maxRetryAfterS = 10
	assertPrefix   = "frostauth:assertion:v1"
)

var PublicKeys = map[string]string{ "k2": "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo" }

const (
	CodeConfig          = "CONFIG"
	CodeNetwork         = "NETWORK"
	CodeTimeout         = "TIMEOUT"
	CodeNotInit         = "NOT_INITIALIZED"
	CodeNotActivated    = "NOT_ACTIVATED"
	CodeServerError     = "SERVER_ERROR"
	CodeSignature       = "SIGNATURE"
	CodeRateLimited     = "RATE_LIMITED"
)

type Error struct {
	Code        string
	Status      int
	Retryable   bool
	RequestID   string
	RetryAfterS int
	msg         string
}

func (e *Error) Error() string { return e.msg }

func (e *Error) NeedsActivation() bool { return e.Status == 404 && !e.Retryable }

func (e *Error) Terminal() bool { return !e.Retryable && !e.NeedsActivation() && e.Status >= 400 && e.Status < 500 }

func sdkErr(code string, status int, msg string) *Error {
	return &Error{Code: code, Status: status, msg: msg}
}


func spkiToEd25519(b64 string) (ed25519.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		if der, err = base64.URLEncoding.DecodeString(strings.TrimSpace(b64)); err != nil {
			return nil, fmt.Errorf("not a usable Ed25519 public key: %w", err)
		}
	}
	if len(der) == 32 {
		return ed25519.PublicKey(der), nil
	}
	if len(der) == 44 {
		return ed25519.PublicKey(der[12:]), nil
	}
	return nil, fmt.Errorf("not a usable Ed25519 public key (bad SPKI length %d)", len(der))
}

type keyEntry struct {
	id  string
	key ed25519.PublicKey
}

type keyRing struct{ entries []keyEntry }

func (r keyRing) size() int { return len(r.entries) }

func (r keyRing) selectByID(id string) []ed25519.PublicKey {
	id = strings.TrimSpace(id)
	if id == "" {
		out := make([]ed25519.PublicKey, 0, len(r.entries))
		for _, e := range r.entries {
			out = append(out, e.key)
		}
		return out
	}
	for _, e := range r.entries {
		if e.id == id {
			return []ed25519.PublicKey{e.key}
		}
	}
	return nil
}

func newKeyRing(value any) (keyRing, error) {
	var raw map[string]string
	switch v := value.(type) {
	case nil:
		return keyRing{}, nil
	case map[string]string:
		raw = v
	case string:
		if strings.TrimSpace(v) == "" {
			return keyRing{}, nil
		}
		raw = map[string]string{"": v}
	default:
		return keyRing{}, sdkErr(CodeConfig, 0, "publicKey must be a map[string]string or a single key string")
	}
	ring := keyRing{}
	for id, v := range raw {
		if strings.TrimSpace(v) == "" {
			continue
		}
		key, err := spkiToEd25519(v)
		if err != nil {
			return keyRing{}, sdkErr(CodeConfig, 0, err.Error())
		}
		ring.entries = append(ring.entries, keyEntry{id: id, key: key})
	}
	return ring, nil
}


func claimString(c map[string]any) []byte {
	g := func(k string) string {
		if v, ok := c[k].(string); ok {
			return v
		}
		return ""
	}
	return []byte(strings.Join([]string{
		assertPrefix, "1", g("lic"), g("pid"), g("dev"), g("hwid"), g("status"), g("tier"),
		g("exp"), g("iat"), g("nbf"), g("naf"),
	}, "\n"))
}

func parseMS(v any) (int64, bool) {
	switch t := v.(type) {
	case string:
		if ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(t)); err == nil {
			return ts.UnixMilli(), true
		}
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(t)); err == nil {
			return ts.UnixMilli(), true
		}
	case float64:
		return int64(t), true
	case int64:
		return t, true
	}
	return 0, false
}

func VerifyAssertion(assertion string, pinned map[string]string, opts ...map[string]any) (map[string]any, bool, string) {
	ring, err := newKeyRing(pinned)
	if err != nil || ring.size() == 0 {
		return nil, false, "no pinned public key"
	}
	hwid := ""
	at := time.Now().UnixMilli()
	if len(opts) > 0 {
		if v, ok := opts[0]["hwid"].(string); ok {
			hwid = v
		}
		if v, ok := opts[0]["at"].(int64); ok {
			at = v
		}
		if v, ok := opts[0]["at"].(float64); ok {
			at = int64(v)
		}
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, false, "malformed"
	}
	var claims map[string]any
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false, "unreadable"
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false, "unreadable"
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, "unreadable"
	}
	ok := false
	for _, key := range ring.selectByID(parts[2]) {
		if ed25519.Verify(key, claimString(claims), sig) {
			ok = true
			break
		}
	}
	if !ok {
		return claims, false, "signature does not verify"
	}
	if hwid != "" && claims["hwid"] != hwid {
		return claims, false, "issued for a different machine"
	}
	nbf, okNbf := parseMS(claims["nbf"])
	naf, okNaf := parseMS(claims["naf"])
	if !okNbf || !okNaf || naf <= nbf {
		return claims, false, "offline window is missing or unreadable"
	}
	if at < nbf {
		return claims, false, "not yet valid"
	}
	if at > naf {
		return claims, false, "offline period has run out"
	}
	if expRaw, present := claims["exp"]; present && fmt.Sprint(expRaw) != "" {
		if exp, okExp := parseMS(expRaw); !okExp || at > exp {
			return claims, false, "licence expired"
		}
	}
	return claims, true, ""
}


func runCmd(timeout time.Duration, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func safeUser() string {
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	parts := strings.Split(strings.TrimRight(h, `/\`), string(os.PathSeparator))
	return parts[len(parts)-1]
}

var machineCache string

func rawMachineID() string {
	if machineCache != "" {
		return machineCache
	}
	switch runtime.GOOS {
	case "windows":
		if out, ok := runCmd(5*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"); ok {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "MachineGuid") {
					if i := strings.Index(line, "REG_SZ"); i >= 0 {
						machineCache = strings.TrimSpace(line[i+6:])
						return machineCache
					}
				}
			}
		}
	case "darwin":
		if out, ok := runCmd(5*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); ok {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, `"IOPlatformUUID"`) {
					if i := strings.Index(line, `" = "`); i >= 0 {
						v := strings.TrimSuffix(line[i+5:], `"`)
						machineCache = strings.TrimSpace(v)
						return machineCache
					}
				}
			}
		}
	case "linux":
		if b, err := os.ReadFile("/etc/machine-id"); err == nil && len(bytes.TrimSpace(b)) > 0 {
			machineCache = strings.TrimSpace(string(b))
			return machineCache
		}
		if b, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil && len(bytes.TrimSpace(b)) > 0 {
			machineCache = strings.TrimSpace(string(b))
			return machineCache
		}
	}
	host, _ := os.Hostname()
	machineCache = fmt.Sprintf("fallback:%s:%s:%s", host, safeUser(), runtime.GOOS)
	return machineCache
}

func HardwareID(scope string) string {
	if scope == "" {
		scope = "frostauth"
	}
	sum := sha256.Sum256([]byte(scope + "|" + rawMachineID()))
	return hex(sum[:])
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func facet(v string) string { return hex(sum32(v))[:32] }

func sum32(v string) []byte {
	s := sha256.Sum256([]byte(v))
	return s[:]
}

var vmMacPrefixes = []string{
	"00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27", "0a:00:27",
	"00:15:5d", "00:1c:42", "52:54:00", "00:16:3e",
}

var vmNamePattern = []string{
	"vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "hyper-v", "hyperv",
	"parallels", "bhyve", "virtual machine", "innotek",
}

func looksVM(s string) bool {
	s = strings.ToLower(s)
	for _, p := range vmNamePattern {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func HardwareProfile() ([]map[string]string, bool) {
	var cpuModel string
	nCPU := runtime.NumCPU()
	switch runtime.GOOS {
	case "windows":
		if out, ok := runCmd(5*time.Second, "reg", "query", `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "/v", "ProcessorNameString"); ok {
			if i := strings.Index(out, "REG_SZ"); i >= 0 {
				cpuModel = strings.TrimSpace(out[i+7:])
			}
		}
	case "darwin":
		if out, ok := runCmd(5*time.Second, "sysctl", "-n", "machdep.cpu.brand_string"); ok {
			cpuModel = strings.TrimSpace(out)
		}
	case "linux":
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "model name") {
					if i := strings.Index(line, ":"); i >= 0 {
						cpuModel = strings.TrimSpace(line[i+1:])
					}
					break
				}
			}
		}
	}
	host, _ := os.Hostname()

	components := []map[string]string{
		{"n": "cpu", "v": facet(fmt.Sprintf("%s|%d", cpuModel, nCPU))},
		{"n": "ram", "v": facet("unknown")},
		{"n": "arch", "v": facet(runtime.GOARCH)},
		{"n": "platform", "v": facet(runtime.GOOS)},
		{"n": "host", "v": facet(host)},
	}

	allVM, anyNIC := true, false
	var macs []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagLoopback != 0 || ifc.HardwareAddr == nil {
				continue
			}
			mac := ifc.HardwareAddr.String()
			if mac == "" || mac == "00:00:00:00:00:00" {
				continue
			}
			anyNIC = true
			macs = append(macs, strings.ToLower(mac))
			vm := false
			for _, p := range vmMacPrefixes {
				if strings.HasPrefix(mac, p) {
					vm = true
					break
				}
			}
			if !vm {
				allVM = false
			}
		}
	}
	if len(macs) > 0 {
		sortStrings(macs)
		joined := strings.Join(macs, ",")
		components = append(components, map[string]string{"n": "mac", "v": facet(joined)})
	} else {
		allVM = false
	}

	virtual := (anyNIC && allVM) || looksVM(cpuModel)
	return components, virtual
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}


func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 127 || v4[0] == 10 ||
			(v4[0] == 192 && v4[1] == 168) ||
			(v4[0] == 169 && v4[1] == 254) ||
			(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
			(v4[0] == 0)
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	return ip[0] == 0xfc || ip[0] == 0xfd
}


type envelope struct {
	Error    any `json:"error"`
	Response struct {
		ErrorCode string          `json:"errorCode"`
		Message   string          `json:"message"`
		Data      json.RawMessage `json:"data"`
	} `json:"response"`
	Success bool   `json:"success"`
	Message string `json:"message"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	AppName   string `json:"app_name"`
	OwnerID   string `json:"owner_id"`
	Errors    map[string]string `json:"errors"`
}


type Options struct {
	Owner   string
	Product string
	Version string

	BaseURL            string
	TimeoutMS          int
	Retries            int
	OfflineGraceSeconds int
	PublicKey          map[string]string
	AllowInsecure      bool
	AllowPrivateDNS    bool
	HardwareIDOverride string
	CollectHardware    bool
}

type sessionInfo struct {
	Token            string `json:"token"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
}

type offlineInfo struct {
	Assertion string `json:"assertion"`
	NotAfter  string `json:"notAfter"`
}

type Snapshot struct {
	App           map[string]any `json:"app"`
	License       map[string]any `json:"license"`
	Product       map[string]any `json:"product"`
	Device        map[string]any `json:"device"`
	User          string         `json:"user"`
	Account       map[string]any `json:"account"`
	Subscriptions []any          `json:"subscriptions"`
	Valid         bool           `json:"valid"`
}

type FrostAuth struct {
	Owner, Product, Version string
	BaseURL                 string
	Timeout                 time.Duration
	Retries                 int
	OfflineGraceSeconds     int
	CollectHardware         bool

	mu         sync.Mutex
	keys       keyRing
	app        map[string]any
	license    map[string]any
	product    map[string]any
	device     map[string]any
	user       string
	account    map[string]any
	subs       []any
	sess       *sessionInfo
	machineKey string
	machineID  string
	hwOverride string
	assertion  string
	offlineUntil string
	offlineSince *time.Time
	initialized bool
	activated  bool
	closed     bool
	hbStop     chan struct{}
	hbRunning  bool

	OnActivated       func(Snapshot)
	OnValidated       func(Snapshot)
	OnLoggedIn        func(Snapshot)
	OnUpdateAvailable func(current, latest string)
	OnOffline         func(err *Error, secondsOffline int, verified bool)
	OnInvalid         func(err *Error)
	OnNeedsActivation func(err *Error)
}

func New(o Options) (*FrostAuth, error) {
	for _, p := range []struct {
		name, v string
	}{
		{"owner", o.Owner}, {"product", o.Product}, {"version", o.Version},
	} {
		if strings.TrimSpace(p.v) == "" {
			return nil, sdkErr(CodeConfig, 0, p.name+" is required")
		}
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, sdkErr(CodeConfig, 0, "baseUrl is not a valid URL")
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !loopback && !o.AllowInsecure {
		return nil, sdkErr(CodeConfig, 0, "refusing to send a licence key over plain http; use https or AllowInsecure:true")
	}
	ring, err := newKeyRing(o.PublicKey)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(o.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	retries := o.Retries
	grace := o.OfflineGraceSeconds
	if grace == 0 {
		grace = 900
	}
	return &FrostAuth{
		Owner: o.Owner, Product: o.Product, Version: o.Version,
		BaseURL: base, Timeout: timeout, Retries: retries,
		OfflineGraceSeconds: grace,
		CollectHardware:     o.CollectHardware != false,
		keys:                ring,
		hwOverride:          o.HardwareIDOverride,
	}, nil
}

func (c *FrostAuth) Valid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activated && !c.closed
}

func (c *FrostAuth) Init() (map[string]any, error) {
	if err := c.assertRealHost(); err != nil {
		return nil, err
	}
	path := "/api/v1/settings/catalog/" + url.PathEscape(c.Owner) + "/" + url.PathEscape(c.Product)
	raw, status, _, err := c.request("GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	var body envelope
	_ = json.Unmarshal(raw, &body)
	if !body.Success {
		code := ""
		if s, ok := body.Error.(string); ok {
			code = s
		}
		if code == "" {
			code = "APP_NOT_FOUND"
		}
		return nil, &Error{Code: code, Status: status, msg: orDefault(body.Message, "Application not found")}
	}
	pinned, ok := PublicKeys[body.KeyID]
	if body.KeyID == "" || !ok || body.PublicKey != pinned {
		return nil, &Error{Code: CodeSignature, Status: 401, msg: "server identity check failed — refusing to continue"}
	}
	key, err := spkiToEd25519(pinned)
	if err != nil {
		return nil, sdkErr(CodeConfig, 0, "built-in pinned key is malformed")
	}
	c.mu.Lock()
	c.keys = keyRing{entries: []keyEntry{{id: body.KeyID, key: key}}}
	c.app = map[string]any{
		"name": body.AppName, "ownerId": body.OwnerID, "messages": body.Errors,
	}
	c.initialized = true
	c.mu.Unlock()
	return c.App(), nil
}

func (c *FrostAuth) App() map[string]any { c.mu.Lock(); defer c.mu.Unlock(); return c.app }

func (c *FrostAuth) assertInit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return sdkErr(CodeNotInit, 0, "call Init() before anything else")
	}
	return nil
}

func (c *FrostAuth) resolveMachineID() (string, error) {
	c.mu.Lock()
	override, existing := c.hwOverride, c.machineID
	c.mu.Unlock()
	if existing != "" {
		return existing, nil
	}
	if override != "" {
		c.mu.Lock()
		c.machineID = override
		c.mu.Unlock()
		return override, nil
	}
	c.mu.Lock()
	app := c.app
	c.mu.Unlock()
	scope := c.Owner
	if s, ok := app["ownerId"].(string); ok && s != "" {
		scope = s
	}
	id := HardwareID(scope)
	c.mu.Lock()
	c.machineID = id
	c.mu.Unlock()
	return id, nil
}

func (c *FrostAuth) hardwareExtra() (map[string]any, error) {
	if !c.CollectHardware {
		return map[string]any{}, nil
	}
	comps, virtual := HardwareProfile()
	list := make([]map[string]string, 0, len(comps))
	list = append(list, comps...)
	return map[string]any{"components": list, "virtual": virtual}, nil
}

func (c *FrostAuth) Activate(key string, extra map[string]string) (Snapshot, error) {
	if err := c.assertInit(); err != nil {
		return Snapshot{}, err
	}
	if strings.TrimSpace(key) == "" {
		return Snapshot{}, sdkErr(CodeConfig, 0, "licence key is required")
	}
	hwid, err := c.resolveMachineID()
	if err != nil {
		return Snapshot{}, err
	}
	hw, _ := c.hardwareExtra()
	body := map[string]any{
		"key": key, "hwid": hwid, "os": runtime.GOOS, "appVersion": c.Version,
	}
	for k, v := range hw {
		body[k] = v
	}
	if extra != nil {
		if extra["hash"] != "" {
			body["hash"] = extra["hash"]
		}
		if extra["label"] != "" {
			body["label"] = truncate(extra["label"], 64)
		}
	}
	data, err := c.requestEnvelope("POST", "/api/v1/activate", body)
	if err != nil {
		return Snapshot{}, err
	}
	c.adopt(data)
	c.mu.Lock()
	c.activated = true
	c.offlineSince = nil
	snap := c.snapshotLocked()
	c.mu.Unlock()
	if c.OnActivated != nil {
		c.OnActivated(snap)
	}
	return snap, nil
}

func (c *FrostAuth) Register(key, username, password string, extra map[string]string) (Snapshot, error) {
	if err := c.assertInit(); err != nil {
		return Snapshot{}, err
	}
	if strings.TrimSpace(key) == "" {
		return Snapshot{}, sdkErr(CodeConfig, 0, "licence key is required")
	}
	hwid, err := c.resolveMachineID()
	if err != nil {
		return Snapshot{}, err
	}
	hw, _ := c.hardwareExtra()
	body := map[string]any{
		"key": key, "username": username, "password": password,
		"hwid": hwid, "os": runtime.GOOS, "appVersion": c.Version,
	}
	for k, v := range hw {
		body[k] = v
	}
	if extra != nil {
		if extra["hash"] != "" {
			body["hash"] = extra["hash"]
		}
		if extra["label"] != "" {
			body["label"] = truncate(extra["label"], 64)
		}
	}
	data, err := c.requestEnvelope("POST", "/api/v1/sdk/register", body)
	if err != nil {
		return Snapshot{}, err
	}
	c.adopt(data)
	c.mu.Lock()
	c.activated = true
	c.offlineSince = nil
	snap := c.snapshotLocked()
	c.mu.Unlock()
	if c.OnActivated != nil {
		c.OnActivated(snap)
	}
	return snap, nil
}

func (c *FrostAuth) Login(username, password string, extra map[string]string) (Snapshot, error) {
	if err := c.assertInit(); err != nil {
		return Snapshot{}, err
	}
	hwid, err := c.resolveMachineID()
	if err != nil {
		return Snapshot{}, err
	}
	hw, _ := c.hardwareExtra()
	body := map[string]any{
		"owner": c.Owner, "product": c.Product, "username": username, "password": password,
		"hwid": hwid, "os": runtime.GOOS, "appVersion": c.Version,
	}
	for k, v := range hw {
		body[k] = v
	}
	if extra != nil {
		if extra["twofa"] != "" {
			body["twofa"] = extra["twofa"]
		}
		if extra["hash"] != "" {
			body["hash"] = extra["hash"]
		}
		if extra["label"] != "" {
			body["label"] = truncate(extra["label"], 64)
		}
	}
	data, err := c.requestEnvelope("POST", "/api/v1/sdk/login", body)
	if err != nil {
		return Snapshot{}, err
	}
	c.adopt(data)
	c.mu.Lock()
	c.activated = true
	c.offlineSince = nil
	snap := c.snapshotLocked()
	c.mu.Unlock()
	if c.OnLoggedIn != nil {
		c.OnLoggedIn(snap)
	}
	if c.OnActivated != nil {
		c.OnActivated(snap)
	}
	return snap, nil
}

func (c *FrostAuth) Upgrade(username, password, key string) (map[string]any, error) {
	if err := c.assertInit(); err != nil {
		return nil, err
	}
	return c.requestEnvelope("POST", "/api/v1/sdk/upgrade", map[string]any{
		"owner": c.Owner, "product": c.Product,
		"username": username, "password": password, "key": key,
	})
}

func (c *FrostAuth) authed(method, path string, body map[string]any) (map[string]any, error) {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil || sess.Token == "" {
		return nil, sdkErr(CodeNotActivated, 0, "this call needs a session — activate or sign in first")
	}
	return c.requestEnvelope(method, path, body, sess.Token)
}

func (c *FrostAuth) Logout() (map[string]any, error) {
	c.mu.Lock()
	hasToken := c.sess != nil && c.sess.Token != ""
	c.mu.Unlock()
	if !hasToken {
		c.Close()
		return map[string]any{"signedOut": true}, nil
	}
	defer c.Close()
	return c.authed("POST", "/api/v1/sdk/logout", nil)
}

func (c *FrostAuth) Session() (Snapshot, error) {
	data, err := c.authed("GET", "/api/v1/sdk/session", nil)
	if err != nil {
		return Snapshot{}, err
	}
	c.adopt(data)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked(), nil
}

func (c *FrostAuth) Variable(key string) (string, error) {
	data, err := c.authed("GET", "/api/v1/sdk/vars/app/"+url.PathEscape(key), nil)
	if err != nil {
		return "", err
	}
	return stringField(data, "value"), nil
}

func (c *FrostAuth) ListVars() ([]any, error) {
	data, err := c.authed("GET", "/api/v1/sdk/vars/user", nil)
	if err != nil {
		return nil, err
	}
	if v, ok := data["variables"].([]any); ok {
		return v, nil
	}
	return nil, nil
}

func (c *FrostAuth) GetVar(key string) (string, error) {
	data, err := c.authed("GET", "/api/v1/sdk/vars/user/"+url.PathEscape(key), nil)
	if err != nil {
		return "", err
	}
	return stringField(data, "value"), nil
}

func (c *FrostAuth) SetVar(key, value string) (map[string]any, error) {
	return c.authed("PUT", "/api/v1/sdk/vars/user/"+url.PathEscape(key), map[string]any{"value": value})
}

func (c *FrostAuth) ChangeUsername(username, password string) (map[string]any, error) {
	data, err := c.authed("PATCH", "/api/v1/sdk/username", map[string]any{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.account != nil {
		c.account["username"] = data["username"]
	}
	if s, ok := data["username"].(string); ok {
		c.user = s
	}
	c.mu.Unlock()
	return data, nil
}

func (c *FrostAuth) Log(message string) (map[string]any, error) {
	return c.authed("POST", "/api/v1/sdk/log", map[string]any{"message": truncate(message, 256)})
}

func (c *FrostAuth) Ban(reason string) (map[string]any, error) {
	c.StopHeartbeat()
	defer func() {
		c.mu.Lock()
		c.activated = false
		c.assertion = ""
		c.offlineUntil = ""
		c.mu.Unlock()
	}()
	return c.authed("POST", "/api/v1/sdk/ban", map[string]any{"reason": truncate(reason, 200)})
}

func (c *FrostAuth) FetchOnline() (map[string]any, error) {
	return c.authed("GET", "/api/v1/sdk/online", nil)
}

func (c *FrostAuth) CheckBlacklist() (map[string]any, error) {
	return c.authed("GET", "/api/v1/sdk/checkblacklist", nil)
}

func (c *FrostAuth) Webhook(id string, params, body, conttype string) (map[string]any, error) {
	if strings.TrimSpace(id) == "" {
		return nil, sdkErr(CodeConfig, 0, "webhook id is required")
	}
	payload := map[string]any{}
	if params != "" {
		payload["params"] = truncate(params, 2048)
	}
	if body != "" {
		payload["body"] = truncate(body, 8192)
	}
	if conttype != "" {
		payload["conttype"] = truncate(conttype, 128)
	}
	return c.authed("POST", "/api/v1/sdk/webhook/"+url.PathEscape(id), payload)
}

func (c *FrostAuth) AppData() (map[string]any, error) {
	return c.authed("GET", "/api/v1/sdk/app", nil)
}

func (c *FrostAuth) File(id string) ([]byte, error) {
	return nil, sdkErr(CodeServerError, 0, "File downloads are disabled on this server")
}

func (c *FrostAuth) Validate() (Snapshot, error) {
	if err := c.assertInit(); err != nil {
		return Snapshot{}, err
	}
	c.mu.Lock()
	hasCred := (c.sess != nil && c.sess.Token != "") || c.machineKey != "" || c.hasKeyLocked()
	c.mu.Unlock()
	if !hasCred {
		return Snapshot{}, sdkErr(CodeNotActivated, 0, "activate before validating")
	}

	data, err := c.sendValidate()
	if err == nil {
		c.adopt(data)
		c.mu.Lock()
		c.activated = true
		c.offlineSince = nil
		snap := c.snapshotLocked()
		c.mu.Unlock()
		if c.OnValidated != nil {
			c.OnValidated(snap)
		}
		return snap, nil
	}

	var sdkE *Error
	if !errors.As(err, &sdkE) {
		return Snapshot{}, err
	}
	stale := sdkE.Code == "INVALID_TOKEN" || sdkE.Code == "INVALID_SESSION"
	if stale {
		c.mu.Lock()
		key := c.machineKey
		c.sess = nil
		c.mu.Unlock()
		if key != "" {
			data, err = c.sendValidate()
			if err != nil {
				return Snapshot{}, err
			}
			c.adopt(data)
			c.mu.Lock()
			c.offlineSince = nil
			snap := c.snapshotLocked()
			c.mu.Unlock()
			if c.OnValidated != nil {
				c.OnValidated(snap)
			}
			return snap, nil
		}
	}
	return Snapshot{}, err
}

func (c *FrostAuth) hasKeyLocked() bool { return c.license != nil && c.machineID != "" }

func (c *FrostAuth) StoreKey(key string) {
	c.mu.Lock()
	c.machineKey = key
	c.mu.Unlock()
}

func (c *FrostAuth) sendValidate() (map[string]any, error) {
	hwid, err := c.resolveMachineID()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	sess := c.sess
	key := c.machineKey
	c.mu.Unlock()
	var payload map[string]any
	if sess != nil && sess.Token != "" {
		payload = map[string]any{"token": sess.Token, "hwid": hwid, "appVersion": c.Version, "os": runtime.GOOS}
	} else {
		if key == "" {
			return nil, sdkErr(CodeNotActivated, 0, "activate before validating")
		}
		payload = map[string]any{"key": key, "hwid": hwid, "appVersion": c.Version, "os": runtime.GOOS}
	}
	return c.requestEnvelope("POST", "/api/v1/validate", payload)
}

func (c *FrostAuth) StartHeartbeat(intervalSeconds int) error {
	c.mu.Lock()
	hasCred := (c.sess != nil && c.sess.Token != "") || c.machineKey != "" || c.hasKeyLocked()
	if c.hbRunning {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if !hasCred {
		return sdkErr(CodeNotActivated, 0, "nothing to heartbeat with: activate with a licence key or sign in")
	}
	c.mu.Lock()
	c.closed = false
	c.hbRunning = true
	c.hbStop = make(chan struct{})
	stop := c.hbStop
	c.mu.Unlock()

	go func() {
		for {
			if intervalSeconds > 0 {
				select {
				case <-stop:
					return
				case <-time.After(time.Duration(intervalSeconds) * time.Second):
				}
			} else {
				c.mu.Lock()
				base := 180
				if c.sess != nil && c.sess.HeartbeatSeconds > 0 {
					base = c.sess.HeartbeatSeconds
				}
				c.mu.Unlock()
				if base < 15 {
					base = 15
				}
				wait := time.Duration(base)*time.Second + time.Duration(mrand.Intn(5000))*time.Millisecond
				select {
				case <-stop:
					return
				case <-time.After(wait):
				}
			}

			if _, err := c.Validate(); err != nil {
				var sdkE *Error
				if errors.As(err, &sdkE) {
					switch {
					case sdkE.NeedsActivation():
						c.mu.Lock()
						c.activated = false
						c.mu.Unlock()
						c.StopHeartbeat()
						if c.OnNeedsActivation != nil {
							c.OnNeedsActivation(sdkE)
						}
						return
					case sdkE.Code == CodeSignature || sdkE.Terminal():
						c.mu.Lock()
						c.activated = false
						c.mu.Unlock()
						c.StopHeartbeat()
						if c.OnInvalid != nil {
							c.OnInvalid(sdkE)
						}
						return
					}
				}
				c.mu.Lock()
				now := time.Now()
				if c.offlineSince == nil {
					c.offlineSince = &now
				}
				offlineFor := int(now.Sub(*c.offlineSince).Seconds())
				assertion := c.assertion
				c.mu.Unlock()

				verified := false
				if assertion != "" {
					c.mu.Lock()
					mid := c.machineID
					pins := map[string]string{}
					for _, e := range c.keys.entries {
						pins[e.id] = base64.RawURLEncoding.EncodeToString(derFromEd(e.key))
					}
					c.mu.Unlock()
					_, ok, _ := VerifyAssertion(assertion, pins, map[string]any{"hwid": mid})
					verified = ok
				}
				if c.OnOffline != nil {
					c.OnOffline(sdkE, offlineFor, verified)
				}
				if !verified && (assertion != "" || offlineFor >= c.OfflineGraceSeconds) {
					c.mu.Lock()
					c.activated = false
					c.mu.Unlock()
					c.StopHeartbeat()
					if c.OnInvalid != nil {
						c.OnInvalid(&Error{Code: CodeNetwork, msg: fmt.Sprintf("could not reach the licence server for %ds", offlineFor)})
					}
					return
				}
			}
		}
	}()
	return nil
}

func derFromEd(k ed25519.PublicKey) []byte { return []byte(k) }

func (c *FrostAuth) StopHeartbeat() {
	c.mu.Lock()
	if c.hbStop != nil {
		select {
		case <-c.hbStop:
		default:
			close(c.hbStop)
		}
		c.hbRunning = false
	}
	c.mu.Unlock()
}

func (c *FrostAuth) Close() {
	c.StopHeartbeat()
	c.mu.Lock()
	c.closed = true
	c.machineKey = ""
	c.sess = nil
	c.activated = false
	c.account = nil
	c.subs = nil
	c.assertion = ""
	c.offlineUntil = ""
	c.offlineSince = nil
	c.mu.Unlock()
}

func (c *FrostAuth) CheckOffline() (bool, string) {
	c.mu.Lock()
	assertion := c.assertion
	mid := c.machineID
	pins := map[string]string{}
	for _, e := range c.keys.entries {
		pins[e.id] = base64.RawURLEncoding.EncodeToString(derFromEd(e.key))
	}
	c.mu.Unlock()
	if assertion == "" {
		return false, "no assertion issued yet"
	}
	if len(pins) == 0 {
		return false, "no pinned publicKey to verify against"
	}
	_, ok, reason := VerifyAssertion(assertion, pins, map[string]any{"hwid": mid})
	return ok, reason
}

func (c *FrostAuth) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

func (c *FrostAuth) snapshotLocked() Snapshot {
	return Snapshot{
		App: c.app, License: c.license, Product: c.product, Device: c.device,
		User: c.user, Account: c.account, Subscriptions: c.subs,
		Valid: c.activated && !c.closed,
	}
}

func (c *FrostAuth) adopt(data map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := data["session"].(map[string]any); ok {
		tok, _ := s["token"].(string)
		hb, _ := s["heartbeatSeconds"].(float64)
		c.sess = &sessionInfo{Token: tok, HeartbeatSeconds: int(hb)}
	}
	if v, ok := data["license"].(map[string]any); ok {
		c.license = v
	}
	if v, ok := data["product"].(map[string]any); ok {
		c.product = v
		if ua, _ := v["updateAvailable"].(bool); ua {
			current := c.Version
			latest, _ := v["latest"].(string)
			if latest == "" {
				latest, _ = v["version"].(string)
			}
			dl, _ := v["downloadUrl"].(string)
			_ = dl
			go func() {
				if c.OnUpdateAvailable != nil {
					c.OnUpdateAvailable(current, latest)
				}
			}()
		}
	}
	if v, ok := data["device"].(map[string]any); ok {
		c.device = v
	}
	if v, ok := data["user"].(string); ok {
		c.user = v
	}
	if v, ok := data["account"].(map[string]any); ok {
		c.account = v
	}
	if v, ok := data["subscriptions"].([]any); ok {
		c.subs = v
	}
	if v, ok := data["offline"].(map[string]any); ok {
		if a, ok := v["assertion"].(string); ok && a != "" {
			c.assertion = a
			if na, ok := v["notAfter"].(string); ok {
				c.offlineUntil = na
			}
		}
	}
}


func signingInput(ts, nonce, method, path string, status int, body string) []byte {
	return []byte(strings.Join([]string{ts, nonce, strings.ToUpper(method), path, strconv.Itoa(status), body}, "\n"))
}

func (c *FrostAuth) verifyHeaders(h http.Header, raw string, nonce, method, path string, status int) error {
	c.mu.Lock()
	ring := c.keys
	c.mu.Unlock()
	if ring.size() == 0 {
		return nil
	}
	sig := h.Get("x-frost-signature")
	ts := h.Get("x-frost-timestamp")
	if sig == "" || ts == "" {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: it was not signed"}
	}
	if h.Get("x-frost-nonce") != nonce {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: it answered a different request"}
	}
	tsN, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: bad timestamp"}
	}
	if skew := tsN - time.Now().UnixMilli(); skew > maxSkewMS || skew < -maxSkewMS {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: it was signed too long ago"}
	}
	supplied, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: bad signature encoding"}
	}
	material := signingInput(ts, nonce, method, path, status, raw)
	ok := false
	for _, key := range ring.selectByID(h.Get("x-frost-key-id")) {
		if ed25519.Verify(key, material, supplied) {
			ok = true
			break
		}
	}
	if !ok {
		return &Error{Code: CodeSignature, Status: status, msg: "refusing an unverified answer from the licence server: the signature did not match"}
	}
	return nil
}

func (c *FrostAuth) request(method, path string, body map[string]any, token string) ([]byte, int, http.Header, error) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	nonceB := make([]byte, 16)
	_, _ = rand.Read(nonceB)
	nonce := base64.RawURLEncoding.EncodeToString(nonceB)
	now := time.Now().UnixMilli()

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader(body))
	if err != nil {
		return nil, 0, nil, sdkErr(CodeNetwork, 0, "could not reach the licence server")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("frostauth-sdk-go/%s (%s)", SDKVersion, runtime.GOOS))
	req.Header.Set("X-Frost-Nonce", nonce)
	req.Header.Set("X-Frost-Timestamp", strconv.FormatInt(now, 10))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: c.Timeout}).Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, 0, nil, &Error{Code: CodeTimeout, Retryable: true, msg: fmt.Sprintf("request timed out after %s", c.Timeout)}
		}
		return nil, 0, nil, &Error{Code: CodeNetwork, Retryable: true, msg: "could not reach the licence server"}
	}
	defer resp.Body.Close()
	raw, err := readAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, &Error{Code: CodeNetwork, Retryable: true, msg: "could not read the licence server answer"}
	}
	if resp.StatusCode != 429 || resp.Header.Get("x-frost-signature") != "" {
		if err := c.verifyHeaders(resp.Header, string(raw), nonce, method, path, resp.StatusCode); err != nil {
			return nil, resp.StatusCode, resp.Header, err
		}
	}
	return raw, resp.StatusCode, resp.Header, nil
}

func reader(b map[string]any) *bytes.Reader {
	if b == nil {
		return bytes.NewReader(nil)
	}
	j, _ := json.Marshal(b)
	return bytes.NewReader(j)
}

func readAll(r io.Reader) ([]byte, error) {
	const limit = 8 << 20
	return io.ReadAll(io.LimitReader(r, limit))
}

func (c *FrostAuth) requestEnvelope(method, path string, body map[string]any, token ...string) (map[string]any, error) {
	tok := ""
	if len(token) > 0 {
		tok = token[0]
	}
	retries := c.Retries
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(mrand.Intn(min(300*(1<<attempt), 15000))) * time.Millisecond)
		}
		raw, status, hdr, err := c.request(method, path, body, tok)
		if err != nil {
			var sdkE *Error
			if errors.As(err, &sdkE) && sdkE.Code == CodeSignature {
				return nil, err
			}
			lastErr = err
			continue
		}

		if status == 429 && hdr.Get("x-frost-signature") == "" {
			wait := 2
			if ra, e := strconv.Atoi(hdr.Get("retry-after")); e == nil && ra > 0 && ra <= maxRetryAfterS {
				wait = ra
			}
			lastErr = &Error{Code: CodeRateLimited, Status: 429, Retryable: true, RetryAfterS: wait, msg: "rate limited by the licence server"}
			if attempt < retries {
				time.Sleep(time.Duration(wait) * time.Second)
				continue
			}
			return nil, lastErr
		}

		var env envelope
		_ = json.Unmarshal(raw, &env)

		if status >= 500 {
			if env.Response.ErrorCode != "" {
				return nil, &Error{Code: env.Response.ErrorCode, Status: status, msg: orDefault(env.Response.Message, fmt.Sprintf("request failed (%d)", status))}
			}
			lastErr = &Error{Code: CodeServerError, Status: status, Retryable: true, msg: orDefault(env.Response.Message, "the licence server is having trouble")}
			continue
		}

		if env.Error != nil || status < 200 || status > 299 {
			code := env.Response.ErrorCode
		if s, ok := env.Error.(string); ok && s != "" {
			code = s
		}
		if code == "" {
				code = CodeServerError
			}
			return nil, &Error{Code: code, Status: status, msg: orDefault(env.Response.Message, orDefault(env.Message, fmt.Sprintf("request failed (%d)", status)))}
		}

		var data map[string]any
		if len(env.Response.Data) > 0 {
			if err := json.Unmarshal(env.Response.Data, &data); err != nil || data == nil {
				data = map[string]any{}
			}
		} else {
			data = map[string]any{}
		}
		return data, nil
	}
	if lastErr == nil {
		lastErr = &Error{Code: CodeNetwork, Retryable: true, msg: "request failed"}
	}
	return nil, lastErr
}

func (c *FrostAuth) assertRealHost() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" || net.ParseIP(host) != nil {
		return nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return &Error{Code: CodeNetwork, msg: fmt.Sprintf("cannot resolve the licence server host %q — refusing to continue", host)}
	}
	private := []string{}
	for _, a := range addrs {
		if isPrivateIP(a) {
			private = append(private, a)
		}
	}
	if len(private) > 0 {
		return &Error{Code: CodeNetwork, msg: fmt.Sprintf("%q resolves to loopback or private space (%s) — this is what a hosts-file hijack or licence emulator looks like. Refusing to continue.", host, strings.Join(private, ", "))}
	}
	return nil
}

func stringField(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = big.NewInt
var _ = binary.LittleEndian
