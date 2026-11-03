// SPDX-License-Identifier: AGPL-3.0-or-later

// stamp-demo-modules appends a content hash to every relative module import in
// a tree of ES modules, so that a browser can never pair a fresh entry point
// with a stale cached module.
//
//	stamp-demo-modules site/demo
//
// Why this exists: the CDN in front of the marketing site serves .js with
// cache-control: max-age=31536000 -- a year -- while index.html gets ten
// minutes. The portfolio repo's scripts/cache-bust.py stamps the URLs it can
// see, which means the ones written in HTML attributes and CSS url(), so
// app.js and style.css are covered. The demo's ~68 modules under js/ are
// imported from inside app.js, where no HTML parser can see them, so they were
// never stamped. A returning visitor got a fresh index.html, a fresh app.js and
// year-old modules. A first visit always looked perfect, which is what made it
// hard to spot.
//
// The stamp is transitive: a file's hash is taken after its own imports have
// been rewritten, so a change in a leaf changes the URL of everything that
// reaches it, all the way up to app.js. Stamping each import with the hash of
// its target's original bytes would not do: the browser would keep serving a
// cached importer that still pointed at the old leaf URL. cache-bust.py solves
// the same ordering problem by rewriting stylesheets before the HTML that
// links them; this is that idea applied to a module graph.
//
// Nothing here stamps app.js itself. That URL is written in index.html, so
// cache-bust.py already stamps it with the hash of app.js's bytes -- which now
// change whenever anything app.js imports changes. The chain therefore
// completes without a change to the portfolio repo.
//
// The hash is of content, never a date or a build number, so re-running this
// when nothing has changed produces identical output. scripts/sync-site-demo
// --check depends on that: it regenerates the demo and diffs it against the
// committed copy on every CI run.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// stampLength is how many hex characters of the hash to use. Eight matches
// what the site's own cache-bust.py writes, and the stamp only has to
// distinguish a file from its own earlier versions, not from every other file.
const stampLength = 8

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: stamp-demo-modules <directory>")
		return 2
	}
	stamped, err := stampTree(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "stamp-demo-modules: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "stamped %d module import(s)\n", stamped)
	return 0
}

// module is one JavaScript file in the tree.
type module struct {
	rel     string // slash-separated path from the root, e.g. "js/globe.js"
	source  string
	imports []specifier // the relative ones only; the rest are left alone
	deps    []string    // rel paths of the imports' targets, in import order
	output  string      // source with the stamps written in
	stamp   string
}

// stampTree rewrites every .js file under root in place and returns how many
// import specifiers it stamped.
func stampTree(root string) (int, error) {
	modules, order, err := loadModules(root)
	if err != nil {
		return 0, err
	}
	sorted, err := topological(modules, order)
	if err != nil {
		return 0, err
	}

	stamped := 0
	// Dependencies first, so that by the time a file is rewritten every file
	// it imports already has its final stamp.
	for _, rel := range sorted {
		m := modules[rel]
		var b strings.Builder
		at := 0
		for i, spec := range m.imports {
			dep := modules[m.deps[i]]
			b.WriteString(m.source[at:spec.start])
			b.WriteString(withStamp(spec.value, dep.stamp))
			at = spec.end
			stamped++
		}
		b.WriteString(m.source[at:])
		m.output = b.String()
		m.stamp = hashOf(m.output)
	}

	for _, rel := range order {
		m := modules[rel]
		if m.output == m.source {
			continue
		}
		name := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(name)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(name, []byte(m.output), info.Mode().Perm()); err != nil {
			return 0, err
		}
	}
	return stamped, nil
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:stampLength]
}

// withStamp returns the specifier carrying v=<stamp>. Any other query the
// author wrote is kept, and an existing v= is replaced rather than appended,
// so running this twice over the same tree is a no-op.
func withStamp(spec, stamp string) string {
	// A specifier is base?query#fragment, so the fragment comes off first.
	base, fragment, hadFragment := strings.Cut(spec, "#")
	base, query, _ := strings.Cut(base, "?")
	parts := []string{"v=" + stamp}
	for _, p := range strings.Split(query, "&") {
		if p != "" && !strings.HasPrefix(p, "v=") {
			parts = append(parts, p)
		}
	}
	out := base + "?" + strings.Join(parts, "&")
	if hadFragment {
		out += "#" + fragment
	}
	return out
}

// loadModules reads every .js file under root and resolves its relative
// imports. It returns the modules by path and a sorted list of those paths, so
// that everything downstream is independent of directory iteration order.
func loadModules(root string) (map[string]*module, []string, error) {
	modules := map[string]*module{}
	var order []string

	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(name) != ".js" {
			return nil
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		modules[rel] = &module{rel: rel, source: string(raw)}
		order = append(order, rel)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(order)

	for _, rel := range order {
		m := modules[rel]
		for _, spec := range findSpecifiers(m.source) {
			if !strings.HasPrefix(spec.value, "./") && !strings.HasPrefix(spec.value, "../") {
				continue // a bare or absolute specifier; not ours to stamp
			}
			target, err := resolve(root, rel, spec.value)
			if err != nil {
				return nil, nil, err
			}
			if _, ok := modules[target]; !ok {
				// Every file in the tree was read above, so a relative
				// specifier that resolves to something else points outside the
				// demo or at a file that is not there. Either way the demo is
				// already broken and saying so beats stamping around it.
				return nil, nil, fmt.Errorf("%s imports %q, which is not a .js file in %s", rel, spec.value, root)
			}
			m.imports = append(m.imports, spec)
			m.deps = append(m.deps, target)
		}
	}
	return modules, order, nil
}

// resolve turns a relative specifier in the file at rel into a path from the
// root, and refuses one that would climb out of the tree.
func resolve(root, rel, spec string) (string, error) {
	bare, _, _ := strings.Cut(spec, "?")
	bare, _, _ = strings.Cut(bare, "#")
	target := path.Join(path.Dir(rel), bare)
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", fmt.Errorf("%s imports %q, which is outside %s", rel, spec, root)
	}
	return target, nil
}

// topological returns the modules in dependency-first order.
//
// The demo's graph is acyclic today, and a transitive content hash only has an
// answer while that holds: in a cycle each file's hash would depend on its own
// output. So a cycle is reported rather than worked around, because the fix is
// to break it in the portal's own source.
func topological(modules map[string]*module, order []string) ([]string, error) {
	const (
		unseen = iota
		onStack
		done
	)
	state := map[string]int{}
	var sorted []string
	var stack []string

	var visit func(rel string) error
	visit = func(rel string) error {
		switch state[rel] {
		case done:
			return nil
		case onStack:
			at := slices.Index(stack, rel)
			return fmt.Errorf("import cycle: %s -> %s", strings.Join(stack[at:], " -> "), rel)
		}
		state[rel] = onStack
		stack = append(stack, rel)
		for _, dep := range modules[rel].deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[rel] = done
		sorted = append(sorted, rel)
		return nil
	}

	for _, rel := range order {
		if err := visit(rel); err != nil {
			return nil, err
		}
	}
	if len(sorted) != len(order) {
		return nil, errors.New("internal error: not every module was ordered")
	}
	return sorted, nil
}
