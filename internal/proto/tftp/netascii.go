package tftp

import (
	"bufio"
	"io"
)

// netascii converts a Unix text file to netascii: LF becomes CR LF, and a
// bare CR becomes CR NUL.
type netascii struct {
	r       *bufio.Reader
	pending byte
	has     bool
}

func newNetascii(r io.Reader) *netascii { return &netascii{r: bufio.NewReader(r)} }

func (n *netascii) Read(p []byte) (int, error) {
	i := 0
	for i < len(p) {
		if n.has {
			p[i] = n.pending
			n.has = false
			i++
			continue
		}
		c, err := n.r.ReadByte()
		if err != nil {
			if i > 0 {
				return i, nil
			}
			return 0, err
		}
		switch c {
		case '\n':
			p[i], n.pending, n.has = '\r', '\n', true
		case '\r':
			p[i], n.pending, n.has = '\r', 0, true
		default:
			p[i] = c
		}
		i++
	}
	return i, nil
}
