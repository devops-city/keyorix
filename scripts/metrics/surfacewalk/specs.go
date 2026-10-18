package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// httpMethods are the operation keys of an OpenAPI path item. Other keys
// (parameters, summary, servers, $ref, x-*) are not operations.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// openapiOps returns "METHOD /path" for every operation in the spec.
func openapiOps(file string) ([]string, error) {
	b, err := os.ReadFile(file) // #nosec G304 G703 -- path comes from this dev tool's own -flags, run by hand
	if err != nil {
		return nil, err
	}
	return parseOpenAPI(b)
}

func parseOpenAPI(b []byte) ([]string, error) {
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []string
	for p, item := range doc.Paths {
		for m := range item {
			if httpMethods[strings.ToLower(m)] {
				out = append(out, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

var (
	lineComment  = regexp.MustCompile(`//[^\n]*`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	serviceDecl  = regexp.MustCompile(`service\s+(\w+)\s*\{`)
	rpcDecl      = regexp.MustCompile(`\brpc\s+(\w+)\s*\(`)
)

// grpcMethods returns "Service/Method" for every rpc in every .proto below dir.
func grpcMethods(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error { // #nosec G703 -- dir comes from this dev tool's own -flags, run by hand
		if err != nil || d.IsDir() || filepath.Ext(p) != ".proto" {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- p is a .proto found by walking the repo checkout this tool was pointed at
		if err != nil {
			return err
		}
		out = append(out, parseProto(string(b))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func parseProto(src string) []string {
	src = blockComment.ReplaceAllString(src, "")
	src = lineComment.ReplaceAllString(src, "")
	var out []string
	for _, m := range serviceDecl.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		depth, end := 1, m[1]
		for end < len(src) && depth > 0 {
			switch src[end] {
			case '{':
				depth++
			case '}':
				depth--
			}
			end++
		}
		for _, r := range rpcDecl.FindAllStringSubmatch(src[m[1]:end], -1) {
			out = append(out, name+"/"+r[1])
		}
	}
	return out
}

// npmLock returns "direct <name>" per direct dependency of the root importer
// and "package <name@version>" per distinct locked package. It reads pnpm
// lockfile v6 (top-level dependency blocks) and v9 (importers), from the file
// alone: no install, no network.
func npmLock(file string) ([]string, error) {
	b, err := os.ReadFile(file) // #nosec G304 G703 -- path comes from this dev tool's own -flags, run by hand
	if err != nil {
		return nil, err
	}
	return parseLock(b)
}

type lockDeps struct {
	Dependencies         map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
}

func (d lockDeps) names() map[string]bool {
	out := map[string]bool{}
	for _, m := range []map[string]yaml.Node{d.Dependencies, d.DevDependencies, d.OptionalDependencies} {
		for n := range m {
			out[n] = true
		}
	}
	return out
}

func parseLock(b []byte) ([]string, error) {
	var doc struct {
		lockDeps  `yaml:",inline"`
		Importers map[string]lockDeps  `yaml:"importers"`
		Packages  map[string]yaml.Node `yaml:"packages"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var direct map[string]bool
	if len(doc.Importers) > 0 {
		root, ok := doc.Importers["."]
		if !ok {
			return nil, fmt.Errorf("lockfile has importers but no root importer \".\"")
		}
		direct = root.names()
	} else {
		direct = doc.lockDeps.names()
	}
	var out []string
	for n := range direct {
		out = append(out, "direct "+n)
	}
	pk := map[string]bool{}
	for k := range doc.Packages {
		pk[strings.TrimPrefix(k, "/")] = true
	}
	for k := range pk {
		out = append(out, "package "+k)
	}
	sort.Strings(out)
	return out, nil
}
