package pages

import (
	"embed"
	"html/template"
	"io"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates *template.Template

func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

type TermsData struct {
	AuthRequestID string
	Error         string
}

type ErrorData struct {
	Code    int
	Message string
}

func RenderTerms(w io.Writer, data TermsData) error {
	return templates.ExecuteTemplate(w, "terms.html", data)
}

func RenderError(w io.Writer, data ErrorData) error {
	return templates.ExecuteTemplate(w, "error.html", data)
}
