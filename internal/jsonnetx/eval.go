// Package jsonnetx wraps go-jsonnet evaluation for pgroledef inputs.
package jsonnetx

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-jsonnet"
)

// Options controls evaluation.
type Options struct {
	ExtStrs map[string]string
	JPaths  []string
}

// EvaluateFile evaluates a jsonnet file and returns the resulting JSON.
// The file's own directory is always on the import path.
func EvaluateFile(path string, opts Options) ([]byte, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vm := jsonnet.MakeVM()
	for k, v := range opts.ExtStrs {
		vm.ExtVar(k, v)
	}
	jpaths := append([]string{filepath.Dir(path)}, opts.JPaths...)
	vm.Importer(&jsonnet.FileImporter{JPaths: jpaths})
	out, err := vm.EvaluateAnonymousSnippet(path, string(src))
	if err != nil {
		return nil, fmt.Errorf("evaluate %s: %w", path, err)
	}
	return []byte(out), nil
}
