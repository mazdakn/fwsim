package tests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMatchContextIsFirstParam verifies that every named function in the
// module that accepts a *match.MatchContext parameter has it as the first
// parameter.  The receiver on a method is not considered a parameter for this
// purpose, and function literals (closures) are not checked.
func TestMatchContextIsFirstParam(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	// tests/ lives one level below the module root.
	root := filepath.Dir(filepath.Dir(thisFile))

	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Logf("skipping %s: parse error: %v", path, parseErr)
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			funcDecl, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if funcDecl.Type.Params == nil {
				return true
			}

			// Track the actual parameter position across multi-name fields
			// (e.g. "a, b int" occupies two slots but is one *ast.Field).
			paramPos := 0
			for _, field := range funcDecl.Type.Params.List {
				nameCount := len(field.Names)
				if nameCount == 0 {
					nameCount = 1 // unnamed parameter
				}
				if isMatchContextType(field.Type) && paramPos != 0 {
					pos := fset.Position(funcDecl.Pos())
					t.Errorf("%s: function %s: *match.MatchContext must be the first parameter",
						pos, funcDecl.Name.Name)
				}
				paramPos += nameCount
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking source tree: %v", err)
	}
}

// isMatchContextType reports whether expr is *MatchContext (within the match
// package) or *match.MatchContext (as seen from any other package).
func isMatchContextType(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch t := star.X.(type) {
	case *ast.Ident:
		// Inside the match package itself: *MatchContext
		return t.Name == "MatchContext"
	case *ast.SelectorExpr:
		// From any other package: *match.MatchContext
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "match" && t.Sel.Name == "MatchContext"
	}
	return false
}
