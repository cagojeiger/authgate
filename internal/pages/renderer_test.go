package pages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderAll exercises every page so a template change cannot break one of them
// unnoticed. Each returns the rendered HTML.
func renderAll(t *testing.T, brand Brand) map[string]string {
	t.Helper()
	out := map[string]string{}

	var sb strings.Builder
	if err := RenderDeviceEntry(&sb, DeviceEntryData{Brand: brand, UserCode: "BCDF-GHKM"}); err != nil {
		t.Fatalf("device entry: %v", err)
	}
	out["device_entry"] = sb.String()

	sb.Reset()
	if err := RenderDeviceApprove(&sb, DeviceApproveData{Brand: brand, UserCode: "BCDF-GHKM", CSRFToken: "tok"}); err != nil {
		t.Fatalf("device approve: %v", err)
	}
	out["device_approve"] = sb.String()

	sb.Reset()
	if err := RenderResult(&sb, ResultData{Brand: brand, Success: true, Message: "done"}); err != nil {
		t.Fatalf("result: %v", err)
	}
	out["result"] = sb.String()

	sb.Reset()
	if err := RenderError(&sb, ErrorData{Brand: brand, Code: 403, Message: "nope"}); err != nil {
		t.Fatalf("error: %v", err)
	}
	out["error"] = sb.String()

	return out
}

// pages-001: no page may reference an external origin. These are sign-in
// screens; fetching anything from a third party would disclose the visitor's
// IP address on every render.
func TestRender_NoExternalOrigins(t *testing.T) {
	for name, html := range renderAll(t, Brand{Name: "acme"}) {
		for _, forbidden := range []string{"http://", "https://", "//fonts.", "<script"} {
			if strings.Contains(html, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
	}
}

// pages-002: the operator's brand name reaches every page.
func TestRender_BrandNameAppears(t *testing.T) {
	for name, html := range renderAll(t, Brand{Name: "Acme Identity"}) {
		if !strings.Contains(html, "Acme Identity") {
			t.Errorf("%s does not carry the brand name", name)
		}
	}
}

// pages-003: rendered values are escaped. A user code arrives from a query
// string, so it must never be able to inject markup.
func TestRender_EscapesUntrustedValues(t *testing.T) {
	var sb strings.Builder
	if err := RenderDeviceEntry(&sb, DeviceEntryData{
		Brand:    Brand{Name: "acme"},
		UserCode: `"><img src=x onerror=alert(1)>`,
		Error:    `<script>alert(2)</script>`,
	}); err != nil {
		t.Fatalf("render: %v", err)
	}
	html := sb.String()
	if strings.Contains(html, "<img src=x") || strings.Contains(html, "<script>") {
		t.Fatalf("untrusted value was not escaped:\n%s", html)
	}
}

// pages-004: a supplied logo is inlined, and its absence is not an error —
// authgate ships no brand of its own.
func TestLoadBrand_Logo(t *testing.T) {
	dir := t.TempDir()
	logo := filepath.Join(dir, "mark.svg")
	if err := os.WriteFile(logo, []byte(`<svg viewBox="0 0 8 8"><circle cx="4" cy="4" r="3"/></svg>`), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBrand("acme", logo, "")
	if err != nil {
		t.Fatalf("LoadBrand: %v", err)
	}
	html := renderAll(t, b)["device_entry"]
	if !strings.Contains(html, `<circle cx="4"`) {
		t.Error("logo was not inlined")
	}

	// Without a logo the mark is simply omitted.
	plain, err := LoadBrand("acme", "", "")
	if err != nil {
		t.Fatalf("LoadBrand without logo: %v", err)
	}
	// Match the element, not the stylesheet rule of the same name.
	if strings.Contains(renderAll(t, plain)["device_entry"], `class="brand-mark"`) {
		t.Error("mark element rendered despite no logo being configured")
	}
}

// pages-005: a misconfigured logo fails loudly. A deployment that meant to be
// branded should not quietly render anonymous.
func TestLoadBrand_RejectsBadLogo(t *testing.T) {
	dir := t.TempDir()

	notSVG := filepath.Join(dir, "logo.txt")
	if err := os.WriteFile(notSVG, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(dir, "big.svg")
	if err := os.WriteFile(oversized, append([]byte("<svg "), make([]byte, maxLogoBytes)...), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"missing file": filepath.Join(dir, "nope.svg"),
		"not an SVG":   notSVG,
		"oversized":    oversized,
	} {
		if _, err := LoadBrand("acme", path, ""); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// pages-006: the primary colour is interpolated into a <style> block, so only
// a hex literal is accepted. Anything else would let configuration become CSS.
func TestLoadBrand_PrimaryColor(t *testing.T) {
	b, err := LoadBrand("acme", "", "#ff8800")
	if err != nil {
		t.Fatalf("LoadBrand: %v", err)
	}
	if !strings.Contains(renderAll(t, b)["device_entry"], "--ag-primary: #ff8800") {
		t.Error("primary colour override was not applied")
	}

	for _, bad := range []string{
		"red",
		"#12",
		"#xyzxyz",
		"blue; } body { display:none } :root {",
		"var(--x)",
	} {
		if _, err := LoadBrand("acme", "", bad); err == nil {
			t.Errorf("accepted invalid colour %q", bad)
		}
	}
}

// pages-007: an empty brand name falls back rather than rendering a blank
// header.
func TestLoadBrand_DefaultName(t *testing.T) {
	b, err := LoadBrand("   ", "", "")
	if err != nil {
		t.Fatalf("LoadBrand: %v", err)
	}
	if b.Name != "authgate" {
		t.Errorf("Name = %q, want the authgate fallback", b.Name)
	}
}
