package clientaccess

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// publicKeyword is the scalar form of the access key: "access: public".
const publicKeyword = "public"

// UnmarshalYAML decodes the access key of a client. Two forms are accepted:
//
//	access: public
//
//	access:
//	  allow: {google_workspace_domains: [...], email_domains: [...], emails: [...]}
//	  deny:  {emails: [...]}
//
// The mapping form is decoded with unknown fields rejected no matter how the
// enclosing document is decoded. yaml.v3 does not carry a decoder's
// KnownFields setting into a custom unmarshaler, so without this a misspelled
// rule ("email_domain:") would silently drop out and leave the client open.
func (p *Policy) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.ShortTag() == "!!str" && n.Value == publicKeyword {
			*p = *Public()
			return nil
		}
		return fmt.Errorf("line %d: access must be %q or a mapping with allow and deny", n.Line, publicKeyword)
	case yaml.MappingNode:
	default:
		return fmt.Errorf("line %d: access must be %q or a mapping with allow and deny", n.Line, publicKeyword)
	}

	var raw struct {
		Allow *Rules    `yaml:"allow"`
		Deny  DenyRules `yaml:"deny"`
	}
	if err := decodeStrict(n, &raw); err != nil {
		return fmt.Errorf("line %d: access: %w", n.Line, err)
	}
	if raw.Allow == nil {
		return fmt.Errorf("line %d: access: allow is required; write access: public to admit everyone", n.Line)
	}
	compiled, err := New(*raw.Allow, raw.Deny)
	if err != nil {
		return fmt.Errorf("line %d: access: %w", n.Line, err)
	}
	*p = *compiled
	return nil
}

// decodeStrict decodes a node into v rejecting unknown fields, by re-encoding
// it and running a KnownFields decoder over the result.
func decodeStrict(n *yaml.Node, v any) error {
	data, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
