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

type ErrorData struct {
	BrandName string
	Code      int
	Message   string
}

type DeviceEntryData struct {
	BrandName string
	UserCode  string
	Error     string
}

type DeviceApproveData struct {
	BrandName string
	UserCode  string
	CSRFToken string
}

type ResultData struct {
	BrandName string
	Success   bool
	Message   string
}

func RenderError(w io.Writer, data ErrorData) error {
	return templates.ExecuteTemplate(w, "error.html", data)
}

func RenderDeviceEntry(w io.Writer, data DeviceEntryData) error {
	return templates.ExecuteTemplate(w, "device_entry.html", data)
}

func RenderDeviceApprove(w io.Writer, data DeviceApproveData) error {
	return templates.ExecuteTemplate(w, "device_approve.html", data)
}

func RenderResult(w io.Writer, data ResultData) error {
	return templates.ExecuteTemplate(w, "result.html", data)
}
