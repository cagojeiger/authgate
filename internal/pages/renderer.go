package pages

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// Each page is parsed together with the shared layout in its own template set.
// Parsing them all into one set would not work: every page defines a block
// named "content", so a single set would keep only the last one parsed.
var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"device_entry.html", "device_approve.html", "result.html", "error.html"} {
		pages[name] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+name))
	}
}

// maxLogoBytes caps the inlined brand mark. A logo is a small vector glyph;
// anything larger is a misconfiguration, and the file is embedded in every
// page response.
const maxLogoBytes = 32 * 1024

// hexColor matches the only colour syntax accepted for BRAND_PRIMARY_COLOR.
// The value is interpolated into a <style> block, so anything looser would let
// an operator's config turn into arbitrary CSS.
var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{3,8}$`)

// Brand carries the operator's identity into every rendered page. authgate
// ships no brand of its own: the name falls back to a neutral default and the
// mark is simply absent unless one is supplied.
type Brand struct {
	Name string
	// LogoSVG is inlined verbatim into the page. It is operator-supplied and
	// not sanitized — an operator who can mount a file into the container can
	// already change anything else about the deployment.
	LogoSVG template.HTML
	// PrimaryColor overrides the accent used by buttons, focus rings and
	// links. Empty means the built-in default.
	PrimaryColor string
}

// LoadBrand reads the operator's branding. An unreadable or implausible logo
// is an error rather than a silent fallback: a deployment that meant to be
// branded should not quietly render anonymous.
func LoadBrand(name, logoPath, primaryColor string) (Brand, error) {
	b := Brand{Name: strings.TrimSpace(name)}
	if b.Name == "" {
		b.Name = "authgate"
	}

	if primaryColor != "" {
		if !hexColor.MatchString(primaryColor) {
			return Brand{}, fmt.Errorf("pages: BRAND_PRIMARY_COLOR must be a hex colour like #185fc4, got %q", primaryColor)
		}
		b.PrimaryColor = primaryColor
	}

	if logoPath == "" {
		return b, nil
	}
	//nolint:gosec // Path is operator-controlled configuration, not user input.
	raw, err := os.ReadFile(logoPath)
	if err != nil {
		return Brand{}, fmt.Errorf("pages: read BRAND_LOGO_PATH: %w", err)
	}
	if len(raw) > maxLogoBytes {
		return Brand{}, fmt.Errorf("pages: brand logo is %d bytes, limit is %d", len(raw), maxLogoBytes)
	}
	svg := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(svg, "<svg") && !strings.HasPrefix(svg, "<?xml") {
		return Brand{}, fmt.Errorf("pages: brand logo must be an SVG document")
	}
	b.LogoSVG = template.HTML(svg) //nolint:gosec // See the field comment.
	return b, nil
}

type ErrorData struct {
	Brand     Brand
	PageTitle string
	Code      int
	Message   string
}

type DeviceEntryData struct {
	Brand     Brand
	PageTitle string
	UserCode  string
	Error     string
}

type DeviceApproveData struct {
	Brand     Brand
	PageTitle string
	UserCode  string
	CSRFToken string
}

type ResultData struct {
	Brand     Brand
	PageTitle string
	Success   bool
	Message   string
}

func RenderError(w io.Writer, data ErrorData) error {
	data.PageTitle = "Error"
	return pages["error.html"].ExecuteTemplate(w, "error.html", data)
}

func RenderDeviceEntry(w io.Writer, data DeviceEntryData) error {
	data.PageTitle = "Device sign-in"
	return pages["device_entry.html"].ExecuteTemplate(w, "device_entry.html", data)
}

func RenderDeviceApprove(w io.Writer, data DeviceApproveData) error {
	data.PageTitle = "Device sign-in"
	return pages["device_approve.html"].ExecuteTemplate(w, "device_approve.html", data)
}

func RenderResult(w io.Writer, data ResultData) error {
	data.PageTitle = "Device sign-in"
	return pages["result.html"].ExecuteTemplate(w, "result.html", data)
}
