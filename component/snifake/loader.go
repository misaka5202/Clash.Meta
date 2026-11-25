package snifake

// loader.go reads a Cealing-Host JSON rule file into the generic form the rule
// model consumes: a JSON array whose elements are [domains, sni, ip] triples.
// Base64-encoded payloads and // style comments, which upstream tolerates, are
// handled here as well so that any published Cealing-Host file loads as-is.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadRulesFile reads path as a Cealing-Host JSON rule file.
func LoadRulesFile(path string) ([]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := ParseCealingJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rules, nil
}

// ParseCealingJSON decodes a Cealing-Host document. The input may be plain
// JSON, base64-encoded JSON, or JSON containing // and /* */ comments and
// trailing commas, all of which upstream accepts.
func ParseCealingJSON(raw []byte) ([]any, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("empty rule document")
	}
	if text[0] != '[' {
		// maybe base64
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			text = strings.TrimSpace(string(decoded))
		} else if decoded, err := base64.RawStdEncoding.DecodeString(text); err == nil {
			text = strings.TrimSpace(string(decoded))
		}
	}
	text = stripJSONComments(text)
	var out []any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// stripJSONComments removes // and /* */ comments together with trailing
// commas that would otherwise make encoding/json reject the document.
func stripJSONComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			b.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i++
		default:
			b.WriteByte(c)
		}
	}
	return removeTrailingCommas(b.String())
}

// removeTrailingCommas drops a comma that is directly followed by ] or }.
func removeTrailingCommas(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && (s[j] == ']' || s[j] == '}') {
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
