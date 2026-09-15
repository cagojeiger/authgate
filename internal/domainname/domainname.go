// Package domainname checks DNS names in the ASCII form email addresses and
// configuration use.
package domainname

// Valid reports whether name is a DNS name written as ASCII letters, digits and
// hyphens: dot-separated labels of 1-63 characters that do not start or end
// with a hyphen, 253 characters at most, and no trailing dot. Letters may be
// either case. Internationalized domains qualify only in their punycode
// ("xn--") form.
//
// Anything else can never equal the domain of an address a mail system
// delivers to, so treating it as a domain would only produce silent
// mismatches, or matches through Unicode case folding.
func Valid(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	label := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.':
			if label == 0 || name[i-1] == '-' {
				return false
			}
			label = 0
			continue
		case c == '-':
			if label == 0 {
				return false
			}
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	return label > 0 && name[len(name)-1] != '-'
}
