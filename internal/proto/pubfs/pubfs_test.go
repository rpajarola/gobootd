package pubfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rpajarola/gobootd/internal/inventory"
)

func write(t *testing.T, p, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tree(t *testing.T) (*Tree, string) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "netbsd/amd64/binary/sets/base.tgz"), "base")
	write(t, filepath.Join(dir, "netbsd/README"), "readme")
	write(t, filepath.Join(dir, "solaris/s10.flar"), "flar")
	write(t, filepath.Join(dir, "boot/bsd.rd"), "bsd.rd")
	write(t, filepath.Join(dir, "boot/wild"), "wild")
	write(t, filepath.Join(dir, "secret"), "secret")
	os.Symlink("../../secret", filepath.Join(dir, "netbsd/amd64/escape"))
	os.Symlink("binary/sets", filepath.Join(dir, "netbsd/amd64/sets"))
	h := &inventory.Host{
		Name:     "kali",
		Services: []string{"http", "tftp"},
		Exports: []*inventory.Export{
			{Name: "netbsd", Path: filepath.Join(dir, "netbsd"), ExportPath: "/pub/netbsd"},
			{Name: "flar", Path: filepath.Join(dir, "solaris/s10.flar"), ExportPath: "/pub/solaris/s10.flar"},
			{Name: "remote", Path: dir, ExportPath: "/remote", Server: "other"},
		},
		Files: []*inventory.File{
			{Label: "boot/bsd.rd", Path: filepath.Join(dir, "boot/bsd.rd"), Name: "bsd.rd", Aliases: []string{"bsd"}},
			{Label: "boot/wild", Path: filepath.Join(dir, "boot/wild"), Name: "*"},
			{Label: "secret", Path: filepath.Join(dir, "secret"), Name: "secret", Services: []string{"tftp"}},
		},
	}
	return New(h, "http"), dir
}

func names(t *testing.T, tr *Tree, p string) []string {
	t.Helper()
	list, err := tr.ReadDir(p)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", p, err)
	}
	var out []string
	for _, fi := range list {
		n := fi.Name()
		if fi.IsDir() {
			n += "/"
		}
		out = append(out, n)
	}
	return out
}

func TestReadDir(t *testing.T) {
	tr, _ := tree(t)
	for p, want := range map[string][]string{
		"/":                 []string{"bsd", "bsd.rd", "pub/"},
		"/pub":              []string{"netbsd/", "solaris/"},
		"/pub/solaris":      []string{"s10.flar"},
		"/pub/netbsd":       []string{"README", "amd64/"},
		"/pub/netbsd/amd64": []string{"binary/", "sets/"},
		"/../pub/./netbsd/": []string{"README", "amd64/"},
	} {
		if got := names(t, tr, p); !slices.Equal(got, want) {
			t.Errorf("ReadDir(%s) = %v, want %v", p, got, want)
		}
	}
	if _, err := tr.ReadDir("/bsd.rd"); !IsNotDir(err) {
		t.Errorf("ReadDir of a file: %v", err)
	}
}

func TestOpen(t *testing.T) {
	tr, _ := tree(t)
	for p, want := range map[string]string{
		"/pub/netbsd/amd64/binary/sets/base.tgz": "base",
		"/pub/netbsd/amd64/sets/base.tgz":        "base",
		"/pub/solaris/s10.flar":                  "flar",
		"/bsd.rd":                                "bsd.rd",
		"bsd":                                    "bsd.rd",
	} {
		f, err := tr.Open(p)
		if err != nil {
			t.Errorf("Open(%s): %v", p, err)
			continue
		}
		b, _ := io.ReadAll(f)
		f.Close()
		if string(b) != want {
			t.Errorf("Open(%s) = %q, want %q", p, b, want)
		}
	}
	for _, p := range []string{
		"/pub/netbsd/amd64/escape", // symlink out of the export
		"/secret",                  // tftp only
		"/anything",                // only a wildcard matches
		"/remote/secret",           // served by another server
		"/pub/solaris/other",
		"/pub/netbsd/../../secret",
	} {
		if f, err := tr.Open(p); err == nil {
			f.Close()
			t.Errorf("Open(%s) succeeded", p)
		}
	}
	if _, err := tr.Open("/pub"); !errors.Is(err, ErrIsDir) {
		t.Errorf("Open(/pub) = %v, want ErrIsDir", err)
	}
	if _, err := tr.Stat("/nothing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(/nothing) = %v", err)
	}
}

// An export at the top still shows the files and the other exports.
func TestRootExport(t *testing.T) {
	tr, dir := tree(t)
	tr.host.Exports = append(tr.host.Exports, &inventory.Export{Name: "all", Path: filepath.Join(dir, "boot"), ExportPath: "/"})
	if got, want := names(t, tr, "/"), []string{"bsd", "bsd.rd", "pub/", "wild"}; !slices.Equal(got, want) {
		t.Errorf("ReadDir(/) = %v, want %v", got, want)
	}
	if _, err := tr.Stat("/pub/netbsd/README"); err != nil {
		t.Error(err)
	}
}
