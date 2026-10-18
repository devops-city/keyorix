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
	b, err := os.ReadFile(file)
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
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".proto" {
			return err
		}
		b, err := os.ReadFile(p)
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
	b, err := os.ReadFile(file)
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

func (d lockDeps) names(into map[string]bool) {
	for _, m := range []map[string]yaml.Node{d.Dependencies, d.DevDependencies, d.OptionalDependencies} {
		for n := range m {
			into[n] = true
		}
	}
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
	direct := map[string]bool{}
	if len(doc.Importers) > 0 {
		root, ok := doc.Importers["."]
		if !ok {
			return nil, fmt.Errorf("lockfile has importers but no root importer \".\"")
		}
		root.names(direct)
	} else {
		doc.lockDeps.names(direct)
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
