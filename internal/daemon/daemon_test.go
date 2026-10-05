package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const header = `
resolve {
  ethers = ""
  dns    = false
}
log { file = "bootd.log" }
service "rarp" {}
service "tftp" {}
`

// fakeService reports the host count of the inventory it sees on each tick.
type fakeService struct {
	hosts chan int
	tick  chan struct{}
	err   error
}

func (s *fakeService) Run(ctx context.Context, env *Env) error {
	if s.err != nil {
		return s.err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.tick:
			s.hosts <- len(env.Inventory().Hosts)
		}
	}
}

func writeConfig(t *testing.T, path, hosts string) {
	t.Helper()
	// Write and rename, so a concurrent reload never sees a partial file.
	if err := os.WriteFile(path+".tmp", []byte(header+hosts), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func TestRunReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootd.hcl")
	writeConfig(t, path, `host "a" { mac = "0:0:0:0:0:1" }`)
	svc := &fakeService{hosts: make(chan int), tick: make(chan struct{})}
	Register("rarp", func() Service { return svc })
	t.Cleanup(func() { delete(registry, "rarp") })

	ctx, cancel := context.WithCancel(context.Background())
	reload := make(chan struct{})
	done := make(chan error)
	go func() { done <- Run(ctx, path, reload, &bytes.Buffer{}) }()

	svc.tick <- struct{}{}
	if n := <-svc.hosts; n != 1 {
		t.Errorf("hosts = %d, want 1", n)
	}
	// Each send returns once Run picked it up, so a second send waits
	// until the previous reload has read the file.
	writeConfig(t, path, "host \"a\" { mac = \"0:0:0:0:0:1\" }\nhost \"b\" { mac = \"0:0:0:0:0:2\" }")
	reload <- struct{}{}
	reload <- struct{}{}
	writeConfig(t, path, `host "broken" {`)
	reload <- struct{}{}
	reload <- struct{}{}
	svc.tick <- struct{}{}
	if n := <-svc.hosts; n != 2 {
		t.Errorf("hosts after reload = %d, want 2 (broken config ignored)", n)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run = %v", err)
	}
	log, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "bootd.log"))
	for _, want := range []string{"service not implemented yet", "service=tftp", "configuration has errors, keeping the previous one", "bootd stopped"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log does not contain %q:\n%s", want, log)
		}
	}
}

func TestRunServiceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootd.hcl")
	writeConfig(t, path, `host "a" { mac = "0:0:0:0:0:1" }`)
	Register("rarp", func() Service { return &fakeService{err: errors.New("no such interface")} })
	t.Cleanup(func() { delete(registry, "rarp") })

	errc := make(chan error)
	go func() { errc <- Run(context.Background(), path, nil, &bytes.Buffer{}) }()
	select {
	case err := <-errc:
		if err == nil || err.Error() != "service rarp: no such interface" {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after service failure")
	}
}

func TestRunConfigErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootd.hcl")
	writeConfig(t, path, `host "a" { class = "nope" }`)
	var stderr bytes.Buffer
	if err := Run(context.Background(), path, nil, &stderr); err == nil {
		t.Fatal("Run succeeded with a broken configuration")
	}
	if !strings.Contains(stderr.String(), "Unknown class") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
