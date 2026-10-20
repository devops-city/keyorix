package metricsdoc

// Metric inventory scanner. It reads every non-test Go file in the repository
// (including the operator module) and extracts each Prometheus metric definition
// from the AST, so docs/operations/metrics.md is derived from code rather than
// typed by hand.
//
// Recognised definition forms (anything else that looks like a metric constructor
// but cannot be read statically FAILS the scan rather than being skipped):
//
//	promauto.New{Counter,Gauge,Histogram,Summary}[Vec](Opts{Name, Help}[, []string{labels}])
//	prometheus.New{Counter,Gauge,Histogram,Summary}[Vec](...)   (same shapes)
//	promauto.With(reg).New...(...)
//	prometheus.New{Counter,Gauge}Func(Opts{...}, fn)
//	prometheus.NewDesc("name", "help", []string{labels}, nil)    (const collectors)
//
// Name and Help must be string literals; Namespace/Subsystem fields are rejected
// because they would make the final name invisible to a static scan.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type metricDef struct {
	Name   string
	Type   string // counter | gauge | histogram | summary
	Help   string
	Labels []string
	File   string // repo-relative, forward slashes
	field  string // NewDesc only: the struct field the Desc is stored in
}

var valueTypes = map[string]string{"CounterValue": "counter", "GaugeValue": "gauge", "UntypedValue": "untyped"}

// selName returns the final selector name of e (`c.open` -> "open",
// `prometheus.GaugeValue` -> "GaugeValue"), or "".
func selName(e ast.Expr) string {
	if s, ok := e.(*ast.SelectorExpr); ok {
		return s.Sel.Name
	}
	return ""
}

var ctorTypes = map[string]string{
	"NewCounter": "counter", "NewCounterVec": "counter", "NewCounterFunc": "counter",
	"NewGauge": "gauge", "NewGaugeVec": "gauge", "NewGaugeFunc": "gauge",
	"NewHistogram": "histogram", "NewHistogramVec": "histogram",
	"NewSummary": "summary", "NewSummaryVec": "summary",
}

// scanSkipDirs are directories that never hold server/operator metric definitions.
var scanSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".scratch": true,
	"testdata": true, "web": true, ".gopath": true,
}

func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func scanRepo(root string) ([]metricDef, error) {
	var defs []metricDef
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if scanSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// A Desc has no type of its own. Its type is the ValueType a
		// MustNewConstMetric call in the same file gives the struct field that holds
		// it: `Desc: prometheus.NewDesc(...)` paired with
		// `MustNewConstMetric(c.Desc, prometheus.CounterValue, ...)`.
		descField := map[token.Pos]string{} // NewDesc call position -> struct field
		constType := map[string]string{}    // struct field -> counter|gauge|untyped
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok {
					if c, ok := x.Value.(*ast.CallExpr); ok {
						descField[c.Pos()] = k.Name
					}
				}
			case *ast.CallExpr:
				if s, ok := x.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "MustNewConstMetric" && len(x.Args) >= 2 {
					field, vt := selName(x.Args[0]), selName(x.Args[1])
					if t, ok := valueTypes[vt]; ok && field != "" {
						constType[field] = t
					}
				}
			}
			return true
		})
		first := len(defs)
		var walkErr error
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || walkErr != nil {
				return true
			}
			def, isMetric, derr := parseCall(call, rel)
			if derr != nil {
				walkErr = fmt.Errorf("%s: %w", fset.Position(call.Pos()), derr)
				return false
			}
			if isMetric {
				def.field = descField[call.Pos()]
				defs = append(defs, def)
			}
			return true
		})
		for i := first; i < len(defs); i++ {
			if defs[i].Type == "const" {
				if t, ok := constType[defs[i].field]; ok {
					defs[i].Type = t
				}
			}
		}
		return walkErr
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs, nil
}

func parseCall(call *ast.CallExpr, file string) (metricDef, bool, error) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return metricDef{}, false, nil
	}
	ctor := sel.Sel.Name
	if ctor == "NewDesc" && isIdent(sel.X, "prometheus") {
		return parseDesc(call, file)
	}
	typ, known := ctorTypes[ctor]
	if !known || !isMetricReceiver(sel.X) {
		return metricDef{}, false, nil
	}
	if len(call.Args) == 0 {
		return metricDef{}, false, fmt.Errorf("%s with no arguments", ctor)
	}
	lit, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return metricDef{}, false, fmt.Errorf("%s: opts must be an inline composite literal (cannot scan statically)", ctor)
	}
	def := metricDef{Type: typ, File: file}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return metricDef{}, false, fmt.Errorf("%s: positional opts field", ctor)
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			continue
		}
		switch key.Name {
		case "Name", "Help":
			s, err := stringLit(kv.Value)
			if err != nil {
				return metricDef{}, false, fmt.Errorf("%s %s: %w", ctor, key.Name, err)
			}
			if key.Name == "Name" {
				def.Name = s
			} else {
				def.Help = s
			}
		case "Namespace", "Subsystem":
			return metricDef{}, false, fmt.Errorf("%s: %s is unsupported (name must be a full literal)", ctor, key.Name)
		}
	}
	if def.Name == "" {
		return metricDef{}, false, fmt.Errorf("%s: missing Name", ctor)
	}
	if strings.HasSuffix(ctor, "Vec") {
		if len(call.Args) < 2 {
			return metricDef{}, false, fmt.Errorf("%s %s: missing label names", ctor, def.Name)
		}
		labels, err := stringSlice(call.Args[1])
		if err != nil {
			return metricDef{}, false, fmt.Errorf("%s %s labels: %w", ctor, def.Name, err)
		}
		def.Labels = labels
	}
	return def, true, nil
}

func parseDesc(call *ast.CallExpr, file string) (metricDef, bool, error) {
	if len(call.Args) < 4 {
		return metricDef{}, false, fmt.Errorf("NewDesc: want 4 args")
	}
	name, err := stringLit(call.Args[0])
	if err != nil {
		return metricDef{}, false, fmt.Errorf("NewDesc name: %w", err)
	}
	help, err := stringLit(call.Args[1])
	if err != nil {
		return metricDef{}, false, fmt.Errorf("NewDesc %s help: %w", name, err)
	}
	var labels []string
	if id, ok := call.Args[2].(*ast.Ident); !ok || id.Name != "nil" {
		if labels, err = stringSlice(call.Args[2]); err != nil {
			return metricDef{}, false, fmt.Errorf("NewDesc %s labels: %w", name, err)
		}
	}
	// A Desc carries no type; scanRepo resolves it from MustNewConstMetric.
	return metricDef{Name: name, Type: "const", Help: help, Labels: labels, File: file}, true, nil
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// isMetricReceiver accepts `prometheus`, `promauto` and `promauto.With(x)`.
func isMetricReceiver(e ast.Expr) bool {
	if isIdent(e, "prometheus") || isIdent(e, "promauto") {
		return true
	}
	if c, ok := e.(*ast.CallExpr); ok {
		if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "With" && isIdent(s.X, "promauto") {
			return true
		}
	}
	return false
}

func stringLit(e ast.Expr) (string, error) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", fmt.Errorf("not a string literal")
	}
	return strconv.Unquote(bl.Value)
}

func stringSlice(e ast.Expr) ([]string, error) {
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("not an inline []string literal")
	}
	out := make([]string, 0, len(cl.Elts))
	for _, el := range cl.Elts {
		s, err := stringLit(el)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
