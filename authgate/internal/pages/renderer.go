package pages

import (
	"html/template"
	"net/http"
)

// Renderer handles HTML page rendering
type Renderer struct {
	templates *template.Template
}

// NewRenderer creates a new page renderer
func NewRenderer(templates *template.Template) *Renderer {
	return &Renderer{templates: templates}
}

// ConsentData holds data for the consent page
type ConsentData struct {
	Title       string
	ClientName  string
	ClientID    string
	UserName    string
	UserEmail   string
	Scopes      []string
	State       string
	RedirectURI string
	ReqID       string
}

// RenderConsent renders the consent page
func (r *Renderer) RenderConsent(w http.ResponseWriter, data ConsentData) {
	w.Header().Set("Content-Type", "text/html")

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}} - authgate</title>
    <style>
        body { font-family: sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 480px; width: 100%; padding: 40px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #667eea; font-size: 32px; margin: 0; }
        .user { display: flex; align-items: center; padding: 15px; background: #f8f9fa; border-radius: 8px; margin-bottom: 20px; }
        .user-avatar { width: 48px; height: 48px; background: #667eea; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 20px; margin-right: 15px; }
        .scope-item { display: flex; align-items: center; padding: 12px; background: #f8f9fa; border-radius: 6px; margin-bottom: 10px; }
        .btn { display: block; width: 100%; padding: 14px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; margin-bottom: 10px; }
        .btn-primary { background: #667eea; color: white; }
        .btn-secondary { background: #f0f0f0; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>authgate</h1>
            <p>Authorize {{.ClientName}}</p>
        </div>
        <div class="user">
            <div class="user-avatar">{{firstRune .UserName}}</div>
            <div>
                <div style="font-weight: 600;">{{.UserName}}</div>
                <div style="font-size: 14px; color: #666;">{{.UserEmail}}</div>
            </div>
        </div>
        <p style="margin-bottom: 15px; color: #666;"><strong>{{.ClientName}}</strong> is requesting access to:</p>
        {{range .Scopes}}
        <div class="scope-item">
            <div style="margin-right: 15px; font-size: 20px;">{{scopeIcon .}}</div>
            <div>
                <div style="font-weight: 600; text-transform: capitalize;">{{.}}</div>
            </div>
        </div>
        {{end}}
        <form method="POST" action="/oauth/consent" style="margin-top: 20px;">
            <input type="hidden" name="req_id" value="{{.ReqID}}">
            <button type="submit" name="action" value="approve" class="btn btn-primary" style="width: 100%; padding: 14px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; background: #667eea; color: white; margin-bottom: 10px;">Allow Access</button>
            <button type="submit" name="action" value="deny" class="btn btn-secondary" style="width: 100%; padding: 14px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; background: #f0f0f0; color: #666;">Deny</button>
        </form>
    </div>
</body>
</html>`

	t := template.Must(template.New("consent").Funcs(template.FuncMap{
		"firstRune": func(s string) string {
			if s == "" {
				return "?"
			}
			return string([]rune(s)[0])
		},
		"scopeIcon": func(scope string) string {
			switch scope {
			case "openid":
				return "🔐"
			case "profile":
				return "👤"
			case "email":
				return "✉️"
			default:
				return "🔑"
			}
		},
	}).Parse(tmpl))

	t.Execute(w, data)
}

// DeviceEntryData holds data for device entry page
type DeviceEntryData struct{}

// RenderDeviceEntry renders the device code entry page
func (r *Renderer) RenderDeviceEntry(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Device Authorization - authgate</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
       min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
.container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
             max-width: 480px; width: 100%; padding: 40px; }
.logo { text-align: center; margin-bottom: 30px; }
.logo h1 { color: #667eea; font-size: 32px; margin: 0; }
input { width: 100%; padding: 14px; border: 2px solid #e0e0e0; border-radius: 6px; 
        font-size: 18px; text-align: center; letter-spacing: 2px; margin-bottom: 15px; }
button { width: 100%; padding: 14px; border: none; border-radius: 6px; font-size: 16px; 
         font-weight: 600; cursor: pointer; background: #667eea; color: white; }
</style>
</head>
<body>
<div class="container">
    <div class="logo">
        <h1>authgate</h1>
        <p>Device Authorization</p>
    </div>
    <p style="text-align: center; color: #666; margin-bottom: 20px;">
        Enter the code displayed in your terminal:
    </p>
    <form method="GET" action="/device">
        <input type="text" name="user_code" placeholder="ABCD-EFGH" maxlength="9" 
               style="text-transform: uppercase;" autofocus>
        <button type="submit">Continue</button>
    </form>
</div>
</body>
</html>`))
}

// DeviceApprovalData holds data for device approval page
type DeviceApprovalData struct {
	UserCode string
}

// RenderDeviceApproval renders the device approval page
func (r *Renderer) RenderDeviceApproval(w http.ResponseWriter, data DeviceApprovalData) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Authorize Device - authgate</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
       min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
.container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
             max-width: 480px; width: 100%; padding: 40px; }
.logo { text-align: center; margin-bottom: 30px; }
.logo h1 { color: #667eea; font-size: 32px; margin: 0; }
.code-box { background: #f0f0f0; padding: 20px; border-radius: 8px; text-align: center; 
            font-size: 24px; font-weight: bold; letter-spacing: 4px; margin-bottom: 30px; }
button { width: 100%; padding: 14px; border: none; border-radius: 6px; font-size: 16px; 
         font-weight: 600; cursor: pointer; margin-bottom: 10px; }
.btn-primary { background: #667eea; color: white; }
.btn-secondary { background: #f0f0f0; color: #666; }
</style>
</head>
<body>
<div class="container">
    <div class="logo">
        <h1>authgate</h1>
        <p>Confirm Device Authorization</p>
    </div>
    <p style="text-align: center; color: #666; margin-bottom: 15px;">
        A CLI application is requesting access with this code:
    </p>
    <div class="code-box">` + data.UserCode + `</div>
    <p style="color: #666; margin-bottom: 20px; font-size: 14px;">
        If you initiated this login from a CLI, click "Allow". 
        If you did not, click "Deny".
    </p>
    <form method="POST" action="/device/approve">
        <input type="hidden" name="user_code" value="` + data.UserCode + `">
        <button type="submit" name="action" value="approve" class="btn-primary">Allow</button>
        <button type="submit" name="action" value="deny" class="btn-secondary">Deny</button>
    </form>
</div>
</body>
</html>`))
}

// SuccessData holds data for success pages
type SuccessData struct {
	Title   string
	Message string
}

// RenderSuccess renders a success page
func (r *Renderer) RenderSuccess(w http.ResponseWriter, data SuccessData) {
	icon := "✅"
	if data.Title == "Access Denied" {
		icon = "❌"
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>` + data.Title + ` - authgate</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
       min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
.container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
             max-width: 480px; width: 100%; padding: 40px; text-align: center; }
.success-icon { font-size: 64px; margin-bottom: 20px; }
h1 { color: #333; margin-bottom: 15px; }
p { color: #666; line-height: 1.6; }
</style>
</head>
<body>
<div class="container">
    <div class="success-icon">` + icon + `</div>
    <h1>` + data.Title + `</h1>
    <p>` + data.Message + `</p>
</div>
</body>
</html>`))
}

// ErrorData holds data for error pages
type ErrorData struct {
	Message string
}

// RenderError renders an error page
func (r *Renderer) RenderError(w http.ResponseWriter, data ErrorData) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Error - authgate</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
       min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
.container { background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
             max-width: 480px; width: 100%; padding: 40px; text-align: center; }
.error-icon { font-size: 64px; margin-bottom: 20px; }
h1 { color: #c33; margin-bottom: 15px; }
p { color: #666; }
</style>
</head>
<body>
<div class="container">
    <div class="error-icon">❌</div>
    <h1>Error</h1>
    <p>` + data.Message + `</p>
</div>
</body>
</html>`))
}
