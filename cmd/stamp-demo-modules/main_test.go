// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// write lays out a tree of files, creating directories as needed.
func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func read(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFindSpecifiersRecognisesEveryImportForm(t *testing.T) {
	src := `import a from './a.js';
import './side.js';
export * from "./b.js";
export { c } from './c.js';
import * as THREE from '../vendor/three.module.min.js';
const m = await import('./dyn.js');
const n = import( './spaced.js' );
import {
  many,
} from './multi.js';`

	var got []string
	for _, spec := range findSpecifiers(src) {
		got = append(got, spec.value)
	}
	want := []string{
		"./a.js", "./side.js", "./b.js", "./c.js",
		"../vendor/three.module.min.js", "./dyn.js", "./spaced.js", "./multi.js",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("specifiers:\n got %q\nwant %q", got, want)
	}
}

// The portal's own code contains the sentence "read from ' + src + '" and the
// minified Three.js bundle contains `from ("+Y.width+"`. A regular expression
// over the source reads both as imports, which is why the scanner tracks
// strings, comments, template literals and regular expressions.
func TestFindSpecifiersIgnoresWhatOnlyLooksLikeAnImport(t *testing.T) {
	for name, src := range map[string]string{
		"text in a string":       `const s = 'These figures are read from ' + src + '.';`,
		"text in a template":     "const s = `read from ${src} and from './fake.js'`;",
		"minified three.js":      `let t="log( from ("+Y.width+") )";`,
		"a line comment":         `// import x from './nope.js'`,
		"a block comment":        `/* import x from './nope.js' */`,
		"a property named from":  `const url = row.from; const list = Array.from('abc');`,
		"import.meta":            `const here = import.meta.url;`,
		"a regex holding quotes": `const q = /['"]/; const s = "from './nope.js'";`,
		"division, not a regex":  `const r = total / count; const s = "from './nope.js'";`,
	} {
		if found := findSpecifiers(src); len(found) != 0 {
			t.Errorf("%s: found %d specifier(s), want none: %v", name, len(found), found)
		}
	}
}

// A specifier that is not relative belongs to someone else's resolver, and a
// stamp on it would be meaningless or wrong.
func TestFindSpecifiersKeepsNonRelativeOnesVisibleButStampTreeLeavesThemAlone(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"app.js": `import 'three';
import 'https://example.test/x.js';
import '/absolute.js';
import './leaf.js';`,
		"leaf.js": `export const x = 1;`,
	})
	if _, err := stampTree(root); err != nil {
		t.Fatal(err)
	}
	got := read(t, root, "app.js")
	for _, untouched := range []string{"'three'", "'https://example.test/x.js'", "'/absolute.js'"} {
		if !strings.Contains(got, untouched) {
			t.Errorf("%s was rewritten; only relative specifiers should be stamped:\n%s", untouched, got)
		}
	}
	if !regexp.MustCompile(`'\./leaf\.js\?v=[0-9a-f]{8}'`).MatchString(got) {
		t.Errorf("the relative import was not stamped:\n%s", got)
	}
}

// The property this whole tool exists for: a file's stamp covers its imports'
// stamps, so a change in a leaf reaches every file that can get to it.
func TestStampsAreTransitive(t *testing.T) {
	tree := func(leaf string) map[string]string {
		return map[string]string{
			"app.js":      `import { mid } from './js/mid.js';`,
			"js/mid.js":   `import { leaf } from './leaf.js'; export const mid = leaf;`,
			"js/leaf.js":  leaf,
			"js/other.js": `export const other = 1;`,
		}
	}
	stampOf := func(t *testing.T, leaf string) (string, string) {
		t.Helper()
		root := t.TempDir()
		write(t, root, tree(leaf))
		if _, err := stampTree(root); err != nil {
			t.Fatal(err)
		}
		mid := regexp.MustCompile(`mid\.js\?v=([0-9a-f]+)`).FindStringSubmatch(read(t, root, "app.js"))
		lf := regexp.MustCompile(`leaf\.js\?v=([0-9a-f]+)`).FindStringSubmatch(read(t, root, "js/mid.js"))
		if mid == nil || lf == nil {
			t.Fatal("expected both imports to be stamped")
		}
		return mid[1], lf[1]
	}

	midBefore, leafBefore := stampOf(t, `export const leaf = 1;`)
	midAfter, leafAfter := stampOf(t, `export const leaf = 2;`)

	if leafBefore == leafAfter {
		t.Error("the leaf changed but its stamp did not")
	}
	if midBefore == midAfter {
		t.Error("the leaf changed but its importer's stamp did not; a cached importer would keep pointing at the old leaf URL")
	}

	midAgain, leafAgain := stampOf(t, `export const leaf = 1;`)
	if midAgain != midBefore || leafAgain != leafBefore {
		t.Error("identical input gave different stamps; sync-site-demo --check would fail on every run")
	}
}

// Content hashes, not build numbers: running this twice must change nothing,
// or every CI run would show a diff.
func TestStampingIsIdempotent(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"app.js":  `import './js/a.js';`,
		"js/a.js": `import './b.js';`,
		"js/b.js": `export const b = 1;`,
	})
	if _, err := stampTree(root); err != nil {
		t.Fatal(err)
	}
	first := read(t, root, "app.js") + read(t, root, "js/a.js")
	stamped, err := stampTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if stamped != 2 {
		t.Errorf("stamped %d specifier(s), want 2", stamped)
	}
	if second := read(t, root, "app.js") + read(t, root, "js/a.js"); second != first {
		t.Errorf("a second run changed the output:\n first %q\nsecond %q", first, second)
	}
}

func TestWithStampKeepsOtherQueryPartsAndTheFragment(t *testing.T) {
	for _, c := range []struct{ spec, want string }{
		{"./a.js", "./a.js?v=abc"},
		{"./a.js?v=stale", "./a.js?v=abc"},
		{"./a.js?lang=en", "./a.js?v=abc&lang=en"},
		{"./a.js?v=stale&lang=en", "./a.js?v=abc&lang=en"},
		{"./a.js#frag", "./a.js?v=abc#frag"},
		{"./a.js?lang=en#frag", "./a.js?v=abc&lang=en#frag"},
	} {
		if got := withStamp(c.spec, "abc"); got != c.want {
			t.Errorf("withStamp(%q) = %q, want %q", c.spec, got, c.want)
		}
	}
}

// A transitive content hash has no answer inside a cycle: each file's hash
// would depend on its own output. Say so rather than loop or invent one.
func TestCycleIsReportedRatherThanStamped(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"a.js": `import './b.js';`,
		"b.js": `import './a.js';`,
	})
	_, err := stampTree(root)
	if err == nil {
		t.Fatal("a cycle was accepted")
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestMissingTargetIsReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"app.js": `import './gone.js';`})
	_, err := stampTree(root)
	if err == nil || !strings.Contains(err.Error(), "gone.js") {
		t.Fatalf("want an error naming the missing import, got %v", err)
	}
}

func TestImportOutsideTheTreeIsReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"js/app.js": `import '../../secret.js';`})
	_, err := stampTree(root)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("want an error about escaping the tree, got %v", err)
	}
}

func TestFilePermissionsSurvive(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"app.js": `import './leaf.js';`, "leaf.js": `export const x = 1;`})
	if err := os.Chmod(filepath.Join(root, "app.js"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stampTree(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode is %v, want 0600", info.Mode().Perm())
	}
}

func TestRealMain(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"app.js": `import './leaf.js';`, "leaf.js": `export const x = 1;`})

	var stdout, stderr bytes.Buffer
	if code := realMain([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stamped 1 module import") {
		t.Errorf("stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := realMain(nil, &stdout, &stderr); code != 2 {
		t.Errorf("no argument: exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Errorf("no argument: stderr = %q", stderr.String())
	}

	stderr.Reset()
	if code := realMain([]string{filepath.Join(root, "nowhere")}, &stdout, &stderr); code != 1 {
		t.Errorf("missing directory: exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "stamp-demo-modules:") {
		t.Errorf("missing directory: stderr = %q", stderr.String())
	}
}

// The real demo is the only input that matters, so drive the tool over the
// portal's actual front end rather than only over fixtures.
func TestTheRealPortalFrontEndStampsCleanly(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join("..", "..", "internal", "portal", "web")
	// The same three paths scripts/sync-site-demo copies.
	if err := os.CopyFS(filepath.Join(root, "js"), os.DirFS(filepath.Join(src, "js"))); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(root, "vendor"), os.DirFS(filepath.Join(src, "vendor"))); err != nil {
		t.Fatal(err)
	}
	app, err := os.ReadFile(filepath.Join(src, "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), app, 0o644); err != nil {
		t.Fatal(err)
	}

	stamped, err := stampTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if stamped < 100 {
		t.Errorf("stamped only %d import(s) in the real front end; the scanner is probably missing a form", stamped)
	}

	stampedApp := read(t, root, "app.js")
	// The two dynamic imports pull in the heaviest modules; missing them would
	// leave exactly the files worst to serve stale.
	for _, want := range []string{"./js/globe.js?v=", "./js/flatmap.js?v="} {
		if !strings.Contains(stampedApp, want) {
			t.Errorf("app.js does not contain %q; a dynamic import went unstamped", want)
		}
	}
	// The sentences that defeat a regular expression must come through intact.
	if !strings.Contains(read(t, root, "js/traffic.js"), "read from ' + src + '") {
		t.Error("js/traffic.js's prose was rewritten")
	}
	if left := regexp.MustCompile(`(?:from|import\()\s*'\.\.?/[^'?]*'`).FindString(stampedApp); left != "" {
		t.Errorf("app.js still has an unstamped relative import: %s", left)
	}
}

// The scanner's skipping branches are where a mistake does real damage: miss
// the end of a string or a regex and everything after it is read in the wrong
// state, which can either invent a specifier or lose a real one. These drive
// each branch with the specifier that must, or must not, come out the far end.
func TestFindSpecifiersSkipsAwkwardLiteralsCorrectly(t *testing.T) {
	for name, c := range map[string]struct {
		src  string
		want []string
	}{
		"escaped quote inside a string": {
			src:  `const s = 'it\'s from \'./nope.js\''; import './real.js';`,
			want: []string{"./real.js"},
		},
		"escaped backslash ending a string": {
			src:  `const s = 'a\\'; import './real.js';`,
			want: []string{"./real.js"},
		},
		"an unterminated string stops at the line": {
			src:  "const s = 'oops\nimport './real.js';",
			want: []string{"./real.js"},
		},
		"substitution inside a template": {
			src:  "const s = `a ${ b } from './nope.js'`; import './real.js';",
			want: []string{"./real.js"},
		},
		"a template nested in a substitution": {
			src:  "const s = `a ${ `inner ${x} from './nope.js'` } b`; import './real.js';",
			want: []string{"./real.js"},
		},
		"an escaped backtick inside a template": {
			src:  "const s = `a\\`b`; import './real.js';",
			want: []string{"./real.js"},
		},
		"a string running to the end of the file": {
			src:  "import './real.js'; const s = 'oops",
			want: []string{"./real.js"},
		},
		"a slash that never closes is division, not a regex": {
			src:  "const r = a / b\nimport './real.js';",
			want: []string{"./real.js"},
		},
		"a character class that closes before the regex does": {
			src:  `const r = /[a-z]'"/; import './real.js';`,
			want: []string{"./real.js"},
		},
		"a regex running to the end of the file": {
			src:  `import './real.js'; const r = /oops`,
			want: []string{"./real.js"},
		},
		"an unclosed comment after from": {
			src:  "import x from /* oops",
			want: nil,
		},
		"an unterminated template swallows the rest": {
			src:  "const s = `oops; import './nope.js';",
			want: nil,
		},
		"a slash inside a regex character class": {
			src:  `const r = /[/'"]+/; import './real.js';`,
			want: []string{"./real.js"},
		},
		"an escaped slash inside a regex": {
			src:  `const r = /a\/b'"/; import './real.js';`,
			want: []string{"./real.js"},
		},
		"a regex after return": {
			src:  `function f() { return /'"/; } import './real.js';`,
			want: []string{"./real.js"},
		},
		"a comment between from and the specifier": {
			src:  "import x from /* here */ './real.js';",
			want: []string{"./real.js"},
		},
		"a line comment between from and the specifier": {
			src:  "import x from // here\n './real.js';",
			want: []string{"./real.js"},
		},
		"a comment inside a dynamic import's parentheses": {
			src:  "await import(/* lazy */ './real.js');",
			want: []string{"./real.js"},
		},
		"an escape in a specifier is left alone": {
			src:  `import './re\u0061l.js';`,
			want: nil,
		},
		"an unterminated specifier is not one": {
			src:  "import './real.js\n",
			want: nil,
		},
		"a dynamic import of a variable": {
			src:  `const m = await import(name); import './real.js';`,
			want: []string{"./real.js"},
		},
		"a block comment running to the end of the file": {
			src:  `import './real.js'; /* unclosed`,
			want: []string{"./real.js"},
		},
	} {
		var got []string
		for _, spec := range findSpecifiers(c.src) {
			got = append(got, spec.value)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s:\n got %q\nwant %q", name, got, c.want)
		}
	}
}
