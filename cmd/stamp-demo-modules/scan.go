// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "strings"

// specifier is one module specifier found in a source file: the byte range of
// the text between the quotes, and that text.
type specifier struct {
	start, end int
	value      string
}

// keywordsBeforeRegex are the keywords after which a '/' begins a regular
// expression rather than a division. The scanner needs this because a regex
// may contain quotes, and mistaking /['"]/ for division would leave the
// scanner convinced it was inside a string from there to the end of the file.
var keywordsBeforeRegex = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "case": true, "do": true,
	"else": true, "yield": true, "await": true, "throw": true,
}

func isIdentChar(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// findSpecifiers returns every module specifier in src, in source order.
//
// This walks the source rather than matching a regular expression because the
// portal's own code defeats the obvious regex: js/traffic.js contains the
// sentence "These figures are read from ' + src + '", and the minified Three.js
// bundle contains `from ("+Y.width+"`. Both look exactly like `from '...'` to a
// pattern match, and both are inside string literals. So the scanner tracks
// whether it is in code, a comment, a string, a template literal or a regular
// expression, and only recognises an import form while it is in code.
//
// What it recognises, which is every form the portal uses:
//
//	import x from './a.js'    import './a.js'    export * from './a.js'
//	await import('./a.js')
//
// It is deliberately not a JavaScript parser. It knows the shapes above and
// nothing else, so an import written in a shape no browser accepts (a
// specifier built by concatenation, say) is simply not found — which is the
// right outcome, since there would be no fixed URL to stamp.
func findSpecifiers(src string) []specifier {
	var found []specifier
	// last is the previous character that matters for deciding whether a '/'
	// starts a regular expression, and lastWord the previous identifier.
	var last byte
	var lastWord string

	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i = min(i+2, len(src))
		case c == '\'' || c == '"':
			i = skipString(src, i)
			last, lastWord = c, ""
		case c == '`':
			i = skipTemplate(src, i)
			last, lastWord = c, ""
		case c == '/' && regexCanStart(last, lastWord):
			i = skipRegex(src, i)
			last, lastWord = '/', ""
		case isIdentChar(c) && !(c >= '0' && c <= '9'):
			word, next := readWord(src, i)
			// A property named `from` or `import` is not an import form:
			// Array.from('abc') must not be read as one.
			if last != '.' && (word == "from" || word == "import") {
				if spec, after, ok := specifierAfter(src, next, word == "import"); ok {
					found = append(found, spec)
					i, last, lastWord = after, '\'', ""
					continue
				}
			}
			i, last, lastWord = next, src[next-1], word
		default:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				last, lastWord = c, ""
			}
			i++
		}
	}
	return found
}

func readWord(src string, i int) (string, int) {
	j := i
	for j < len(src) && isIdentChar(src[j]) {
		j++
	}
	return src[i:j], j
}

// regexCanStart reports whether a '/' at this point begins a regular
// expression. A regex may follow an operator, a comma, an open bracket or one
// of the keywords above; after a value — an identifier, a number, a closing
// bracket — the '/' is division instead.
func regexCanStart(last byte, lastWord string) bool {
	if lastWord != "" {
		return keywordsBeforeRegex[lastWord]
	}
	switch last {
	case 0, '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^', '<', '>':
		return true
	}
	return false
}

func skipString(src string, i int) int {
	quote := src[i]
	i++
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
			continue
		case quote:
			return i + 1
		case '\n': // an unterminated literal; stop rather than run on
			return i
		}
		i++
	}
	return i
}

// skipTemplate skips a template literal, following ${...} substitutions so
// that a backtick nested inside one does not look like the closing backtick.
func skipTemplate(src string, i int) int {
	i++
	depth := 0
	for i < len(src) {
		switch {
		case src[i] == '\\':
			i += 2
			continue
		case src[i] == '$' && i+1 < len(src) && src[i+1] == '{':
			depth++
			i += 2
			continue
		case src[i] == '}' && depth > 0:
			depth--
		case src[i] == '`' && depth == 0:
			return i + 1
		case src[i] == '`' && depth > 0:
			i = skipTemplate(src, i)
			continue
		}
		i++
	}
	return i
}

func skipRegex(src string, i int) int {
	i++
	class := false
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
			continue
		case '[':
			class = true
		case ']':
			class = false
		case '\n': // a regex cannot span lines; this was division after all
			return i
		case '/':
			if !class {
				return i + 1
			}
		}
		i++
	}
	return i
}

// specifierAfter reads the specifier that follows the keyword ending at i.
// With dynamic true (the keyword was `import`) it also accepts the call form,
// `import('./a.js')`.
func specifierAfter(src string, i int, dynamic bool) (specifier, int, bool) {
	j := skipSpaceAndComments(src, i)
	if dynamic && j < len(src) && src[j] == '(' {
		j = skipSpaceAndComments(src, j+1)
	}
	if j >= len(src) || (src[j] != '\'' && src[j] != '"') {
		return specifier{}, i, false
	}
	end := skipString(src, j)
	if end <= j+1 || src[end-1] != src[j] {
		return specifier{}, i, false
	}
	value := src[j+1 : end-1]
	// A specifier is a plain URL. An escape in one would mean the quoted text
	// and the URL differ, so leave it alone rather than stamp the wrong bytes.
	if strings.ContainsAny(value, "\\\n") {
		return specifier{}, i, false
	}
	return specifier{start: j + 1, end: end - 1, value: value}, end, true
}

func skipSpaceAndComments(src string, i int) int {
	for i < len(src) {
		switch {
		case src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r':
			i++
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i = min(i+2, len(src))
		default:
			return i
		}
	}
	return i
}
