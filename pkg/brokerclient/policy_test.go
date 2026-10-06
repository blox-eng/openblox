package brokerclient

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/blox-eng/openblox/pkg/sandbox"
)

// defaultPolicyOptions passes every policy option the value the library would
// have used anyway. Resolved Specs are identical to ones where nothing was
// passed, so only recorded intent can tell them apart: this is the case #25
// reports as accepted-and-dropped.
//
// Keyed by the option's function name in package sandbox, which
// TestEveryCreateOptionIsClassified checks against the source.
var defaultPolicyOptions = map[string]struct {
	opt  sandbox.CreateOption
	want string
}{
	"WithImage":   {sandbox.WithImage(""), "image"},
	"WithRuntime": {sandbox.WithRuntime(sandbox.DefaultRuntime), "runtime"},
	"WithUser":    {sandbox.WithUser(sandbox.DefaultUser), "user"},
	"WithEgress":  {sandbox.WithEgress(sandbox.EgressNone), "egress"},
	"WithResources": {sandbox.WithResources(sandbox.Resources{
		CPUs:         sandbox.DefaultCPUs,
		MemoryBytes:  sandbox.DefaultMemoryBytes,
		DiskBytes:    sandbox.DefaultDiskBytes,
		MaxProcesses: sandbox.DefaultMaxProcesses,
	}), "resources"},
	"WithLifetime": {sandbox.WithLifetime(sandbox.Lifetime{
		IdleTimeout: sandbox.DefaultIdleTimeout,
		MaxAge:      sandbox.DefaultMaxAge,
	}), "lifetime"},
	"WithCommandTimeouts": {sandbox.WithCommandTimeouts(
		sandbox.DefaultCommandTimeout, sandbox.MaxCommandTimeout), "timeouts"},
}

// callerOwnedOptions are the CreateOptions that carry no host policy and are
// sent to the daemon.
var callerOwnedOptions = map[string]bool{"WithEnv": true, "WithLabel": true}

func TestCreateRejectsPolicyOptionsSetToTheirDefault(t *testing.T) {
	c := newTestClient(t, nil)
	for name, tc := range defaultPolicyOptions {
		t.Run(name, func(t *testing.T) {
			_, err := c.Create(context.Background(), "a", WithProfile("code-exec"), tc.opt)
			if !errors.Is(err, sandbox.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %q should name %q", err, tc.want)
			}
		})
	}
}

// TestCreateRejectsAnOptionWrittenOutsidePackageSandbox covers a CreateOption
// a caller defines themselves. It writes Spec directly, so nothing in package
// sandbox could have recorded it.
func TestCreateRejectsAnOptionWrittenOutsidePackageSandbox(t *testing.T) {
	c := newTestClient(t, nil)
	custom := func(s *sandbox.Spec) { s.Runtime = sandbox.DefaultRuntime }
	_, err := c.Create(context.Background(), "a", WithProfile("code-exec"), custom)
	if !errors.Is(err, sandbox.ErrInvalid) || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("err = %v, want ErrInvalid naming runtime", err)
	}
}

func TestZeroResourcesOptionIsNotIntent(t *testing.T) {
	// WithResources documents zero fields as "keep the default", so an empty
	// Resources asks for nothing. Rejecting it would refuse a no-op.
	if got := policyFieldsSet(sandbox.WithResources(sandbox.Resources{})); len(got) != 0 {
		t.Errorf("empty WithResources reported %v, want nothing", got)
	}
}

// TestEveryCreateOptionIsClassified fails when package sandbox gains a
// CreateOption that this package has not decided about, so a new policy option
// cannot ship as one the broker client silently drops.
func TestEveryCreateOptionIsClassified(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../sandbox/options.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			continue
		}
		if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || id.Name != "CreateOption" {
			continue
		}
		name := fn.Name.Name
		seen[name] = true
		_, policy := defaultPolicyOptions[name]
		if !policy && !callerOwnedOptions[name] {
			t.Errorf("sandbox.%s is a CreateOption this package has not classified: add it to defaultPolicyOptions (daemon policy) or callerOwnedOptions", name)
		}
	}
	for name := range callerOwnedOptions {
		if !seen[name] {
			t.Errorf("callerOwnedOptions lists %s, which package sandbox no longer defines", name)
		}
	}
	for name := range defaultPolicyOptions {
		if !seen[name] {
			t.Errorf("defaultPolicyOptions lists %s, which package sandbox no longer defines", name)
		}
	}
}
