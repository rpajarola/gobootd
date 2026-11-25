package rpl

import "testing"

func FuzzParse(f *testing.F) {
	f.Add(find())
	f.Add(sendFile(3, 1500))
	f.Fuzz(func(t *testing.T, b []byte) { parse(b) })
}
