// demo-app: web UI for browser OAuth login testing.
// Usage: go run demo/app/main.go
// Docker: serves on :9090
package main

import (
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/kangheeyong/authgate/demo/shared"
)

var (
	authgatePublic   = shared.EnvOr("AUTHGATE_PUBLIC_URL", "http://localhost:8080")
	authgateInternal = shared.EnvOr("AUTHGATE_INTERNAL_URL", authgatePublic)
	clientID         = shared.EnvOr("CLIENT_ID", "test-app")
	cliClientID      = shared.EnvOr("CLI_CLIENT_ID", "cli-client")
	redirectURI      = shared.EnvOr("REDIRECT_URI", "http://localhost:9090/callback")
	listenAddr       = shared.EnvOr("LISTEN_ADDR", ":9090")
	pkceVerifier     string
	tmpl             = template.Must(template.New("").Parse(pageHTML))
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/refresh", handleRefresh)
	mux.HandleFunc("/device", handleDeviceStart)
	mux.HandleFunc("/device/poll", handleDevicePoll)

	slog.Info("demo-app starting", "addr", listenAddr, "authgate", authgatePublic)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "home", map[string]string{"AuthgateURL": authgatePublic, "ClientID": clientID})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	pkceVerifier = shared.RandomString(43)
	params := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"openid profile email offline_access"},
		"state": {shared.RandomString(16)}, "code_challenge": {shared.S256(pkceVerifier)}, "code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, authgatePublic+"/authorize?"+params.Encode(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		tmpl.ExecuteTemplate(w, "error", map[string]string{"Error": e})
		return
	}
	tokens, err := shared.ExchangeCode(authgateInternal, r.URL.Query().Get("code"), clientID, redirectURI, pkceVerifier)
	if err != nil {
		tmpl.ExecuteTemplate(w, "error", map[string]string{"Error": err.Error()})
		return
	}
	at, _ := tokens["access_token"].(string)
	tmpl.ExecuteTemplate(w, "tokens", map[string]any{
		"Tokens": shared.Pretty(tokens), "Userinfo": shared.Pretty(shared.GetUserinfo(authgateInternal, at)), "RawTokens": tokens,
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	tokens, err := shared.RefreshToken(authgateInternal, r.FormValue("refresh_token"), clientID)
	if err != nil {
		tmpl.ExecuteTemplate(w, "error", map[string]string{"Error": err.Error()})
		return
	}
	at, _ := tokens["access_token"].(string)
	tmpl.ExecuteTemplate(w, "tokens", map[string]any{
		"Tokens": shared.Pretty(tokens), "Userinfo": shared.Pretty(shared.GetUserinfo(authgateInternal, at)), "RawTokens": tokens, "Refreshed": true,
	})
}

func handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	result, err := shared.DeviceAuthorize(authgateInternal, cliClientID)
	if err != nil {
		tmpl.ExecuteTemplate(w, "error", map[string]string{"Error": err.Error()})
		return
	}
	tmpl.ExecuteTemplate(w, "device", map[string]any{
		"Result": shared.Pretty(result), "RawResult": result, "AuthgateURL": authgatePublic,
	})
}

func handleDevicePoll(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	body, status := shared.DevicePoll(authgateInternal, r.FormValue("device_code"), cliClientID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

const pageHTML = `
{{define "home"}}<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>authgate demo-app</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;background:#f5f5f5}
.c{background:#fff;border-radius:12px;padding:30px;margin:20px 0;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#333}h2{color:#555;margin-top:0}
.b{display:inline-block;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;cursor:pointer;border:none;margin:5px;color:#fff}
.bb{background:#2563eb}.bg{background:#6b7280}.b:hover{opacity:.9}
code{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:13px}
</style></head><body>
<h1>authgate demo-app</h1>
<div class="c"><h2>Browser Login</h2><p>OAuth 2.0 Authorization Code + PKCE</p>
<a href="/login" class="b bb">Login with authgate</a></div>
<div class="c"><h2>Device Flow (Web)</h2><p>Device Authorization Grant</p>
<a href="/device" class="b bg">Start Device Flow</a></div>
<div class="c" style="opacity:.7"><h2>Config</h2>
<p>authgate: <code>{{.AuthgateURL}}</code> | client: <code>{{.ClientID}}</code></p></div>
</body></html>{{end}}

{{define "tokens"}}<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>authgate demo-app</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;background:#f5f5f5}
.c{background:#fff;border-radius:12px;padding:30px;margin:20px 0;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#333}h2{color:#555;margin-top:0}
pre{background:#1e1e1e;color:#d4d4d4;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px}
.b{display:inline-block;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;cursor:pointer;border:none;margin:5px;color:#fff}
.bb{background:#2563eb}.b:hover{opacity:.9}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:14px;font-weight:600}
.gs{background:#dcfce7;color:#166534}.gi{background:#dbeafe;color:#1e40af}
</style></head><body>
<h1>{{if .Refreshed}}<span class="badge gi">Refreshed</span>{{else}}<span class="badge gs">Login Success</span>{{end}}</h1>
<div class="c"><h2>Userinfo</h2><pre>{{.Userinfo}}</pre></div>
<div class="c"><h2>Tokens</h2><pre>{{.Tokens}}</pre></div>
{{if .RawTokens.refresh_token}}<div class="c"><h2>Actions</h2>
<form action="/refresh" method="POST" style="display:inline"><input type="hidden" name="refresh_token" value="{{.RawTokens.refresh_token}}">
<button type="submit" class="b bb">Refresh Token</button></form>
<a href="/login" class="b bb">Login Again</a> <a href="/" class="b bb">Home</a></div>{{end}}
</body></html>{{end}}

{{define "device"}}<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>authgate demo-app - device</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;background:#f5f5f5}
.c{background:#fff;border-radius:12px;padding:30px;margin:20px 0;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#333}h2{color:#555;margin-top:0}
pre{background:#1e1e1e;color:#d4d4d4;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px}
.cd{font-size:36px;font-weight:700;letter-spacing:4px;text-align:center;padding:20px;background:#f8fafc;border-radius:8px;margin:16px 0}
.b{display:inline-block;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;cursor:pointer;border:none;color:#fff}
.bb{background:#2563eb}
#ps{margin-top:16px;padding:12px;border-radius:8px}
.pl{background:#fef3c7;color:#92400e}.ok{background:#dcfce7;color:#166534}.er{background:#fee2e2;color:#991b1b}
</style></head><body>
<h1>Device Flow</h1>
<div class="c"><h2>Step 1: Approve</h2><div class="cd">{{.RawResult.user_code}}</div>
<p style="text-align:center"><a href="{{.AuthgateURL}}/device?user_code={{.RawResult.user_code}}" target="_blank" class="b bb">Open Approval Page</a></p></div>
<div class="c"><h2>Step 2: Waiting...</h2><div id="ps" class="pl">Polling...</div><pre id="pr"></pre></div>
<script>
const dc="{{.RawResult.device_code}}",iv={{.RawResult.interval}}*1000||5000;let g=true;
async function p(){if(!g)return;try{const r=await fetch("/device/poll",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"device_code="+encodeURIComponent(dc)});const d=await r.json();
if(r.ok&&d.access_token){g=false;document.getElementById("ps").className="ok";document.getElementById("ps").textContent="Token received!";document.getElementById("pr").textContent=JSON.stringify(d,null,2)}
else if(d.error==="authorization_pending"||d.error==="slow_down"){setTimeout(p,iv)}
else{g=false;document.getElementById("ps").className="er";document.getElementById("ps").textContent="Error: "+(d.error||"?");document.getElementById("pr").textContent=JSON.stringify(d,null,2)}}
catch(e){setTimeout(p,iv)}}setTimeout(p,2000);
</script></body></html>{{end}}

{{define "error"}}<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>demo-app error</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;background:#f5f5f5}
.c{background:#fff;border-radius:12px;padding:30px;margin:20px 0;box-shadow:0 2px 8px rgba(0,0,0,.1);border-left:4px solid #dc2626}
.b{display:inline-block;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;color:#fff;background:#2563eb}
</style></head><body>
<div class="c"><h1>Error</h1><p>{{.Error}}</p><a href="/" class="b">Home</a></div>
</body></html>{{end}}
`
