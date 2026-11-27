package smb

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/rpajarola/gobootd/internal/inventory"
)

// FuzzHandle feeds messages to a session with a share connected, which
// must answer or ignore them without panicking or leaving the share.
func FuzzHandle(f *testing.F) {
	c0 := &client{t: &testing.T{}}
	f.Add(c0.message(cmdNegotiate, nil, []byte("\x02LANMAN2.1\x00")))
	f.Add(c0.message(cmdSearch, w(10, attrDirectory), cat(ascii(`\*.*`), []byte{5, 0, 0})))
	f.Add(c0.message(cmdOpen, w(0, 0), ascii(`\A.TXT`)))
	f.Add(c0.message(cmdOpenAndX, w(cmdReadAndX, 40, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0), []byte("A.TXT\x00")))
	f.Add(c0.message(cmdTransaction2, w(14, 0, 10, 100, 0, 0, 0, 0, 0, 14, 68, 0, 0, 1, 1), cat([]byte{0, 0, 0}, w(0x16, 10, 4, 1, 0, 0), []byte("*\x00"))))
	f.Add(c0.message(cmdTransaction, w(20, 0, 10, 100, 0, 0, 0, 0, 0, 20, 78, 0, 0, 0), cat([]byte(`\PIPE\LANMAN`+"\x00"), w(0), []byte("WrLeh\x00B13BWz\x00"), w(1, 100))))
	dir := f.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(dir, "A long name.txt"), []byte("x"), 0o644)
	f.Fuzz(func(t *testing.T, msg []byte) {
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		share := &inventory.Share{Name: "S", Path: dir}
		c := &conn{
			s:        &Server{opts: Options{NetBIOSName: "BOOTD", Workgroup: "WORKGROUP"}},
			host:     &inventory.Host{Name: "pc", Shares: []*inventory.Share{share}},
			log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			trees:    map[uint16]*tree{0: {tid: 0, name: "S", share: share, root: root}},
			files:    map[uint16]*file{},
			searches: map[uint16]*search{},
			maxBuf:   defaultClientBuffer,
		}
		defer c.closeAll()
		for range 2 {
			c.handle(msg)
		}
	})
}
