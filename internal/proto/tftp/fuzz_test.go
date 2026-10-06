package tftp

import (
	"strconv"
	"testing"
	"time"
)

// FuzzRequest parses arbitrary requests and negotiates their options: the
// block size must stay within limits, and the OACK only acknowledges
// options the client sent.
func FuzzRequest(f *testing.F) {
	f.Add([]byte("\x00\x01C0A80105.SUN4C\x00octet\x00"))
	f.Add([]byte("\x00\x01netbsd\x00octet\x00blksize\x001468\x00tsize\x000\x00timeout\x003\x00"))
	f.Add([]byte("\x00\x01x\x00netascii\x00tsize\x000\x00"))
	f.Add([]byte("\x00\x02x\x00octet\x00\x00\x00"))
	s := &Server{opts: Options{Timeout: 2, Retries: 5, MaxBlockSize: 1468}}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseRequest(b)
		if err != nil {
			return
		}
		tr := &transfer{s: s, req: r}
		blksize, oack := tr.negotiate(12345)
		if blksize < minBlockSize || blksize > s.opts.MaxBlockSize {
			t.Fatalf("block size %d", blksize)
		}
		if tr.timeout < time.Second || tr.timeout > 255*time.Second {
			t.Fatalf("timeout %v", tr.timeout)
		}
		if oack == nil {
			return
		}
		got, err := parseOACK(oack)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range got {
			if _, ok := find(r, name); !ok {
				t.Fatalf("acknowledged %s, which the client did not send", name)
			}
			if name == "blksize" && value != strconv.Itoa(blksize) {
				t.Fatalf("acknowledged blksize %s, using %d", value, blksize)
			}
		}
	})
}

func find(r *request, name string) (string, bool) {
	for _, o := range r.options {
		if o.name == name {
			return o.value, true
		}
	}
	return "", false
}

// parseOACK parses an OACK as a client would.
func parseOACK(b []byte) (map[string]string, error) {
	r, err := parseRequest(append([]byte{0, opRRQ}, append(b[2:], "x\x00x\x00"...)...))
	if err != nil {
		return nil, err
	}
	m := map[string]string{r.filename: r.mode}
	for _, o := range r.options {
		m[o.name] = o.value
	}
	delete(m, "x")
	return m, nil
}
