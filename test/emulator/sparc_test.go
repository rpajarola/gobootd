// Package emulator boots emulated machines with their real boot PROMs
// against bootd. PROM images are not part of the repository; tests are
// skipped unless their image is given in the environment.
package emulator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	_ "github.com/rpajarola/gobootd/internal/proto/rarp"
	_ "github.com/rpajarola/gobootd/internal/proto/tftp"
)

// helloSPARC is a sun4m boot program that prints a message through the
// PROM's Forth interpreter and halts back to the ok prompt. It is an a.out
// file, which the OpenBoot PROM loads at 0x4000 and enters with the romvec
// in %o0.
func helloSPARC(msg string) []byte {
	code := []uint32{
		0x9DE3BFA0, // save %sp, -96, %sp
		0xA0100018, // mov %i0, %l0          ! romvec
		0x40000002, // call .+8              ! %o7 = address of this call
		0x01000000, // nop
		0x9003E028, // add %o7, 40, %o0      ! Forth source at offset 48
		0xE204207C, // ld [%l0+0x7c], %l1    ! pv_fortheval (v2 and later)
		0x9FC44000, // call %l1
		0x01000000, // nop
		0xE2042074, // ld [%l0+0x74], %l1    ! pv_halt
		0x9FC44000, // call %l1
		0x01000000, // nop
		0x01000000, // nop
	}
	var text []byte
	for _, c := range code {
		text = binary.BigEndian.AppendUint32(text, c)
	}
	text = append(text, fmt.Sprintf("cr .\" %s\" cr\x00", msg)...)
	for len(text)%8 != 0 {
		text = append(text, 0)
	}
	var b []byte
	for _, v := range []uint32{0x01030107, uint32(len(text)), 0, 0, 0, 0x4000, 0, 0} { // OMAGIC, SPARC
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return append(b, text...)
}

func freePort(t *testing.T) netip.AddrPort {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestSPARCstation5 boots QEMU's SS-5 with the real Sun PROM (OBP 2.x):
// the PROM gets its address with RARP, loads the boot program with TFTP and
// runs it.
//
//	GOBOOTD_SS5_PROM=ss5.bin go test ./test/emulator
//
// QEMU 10.2 and later pad loopback frames, which fails the PROM's LANCE
// loopback self-test; GOBOOTD_QEMU_SPARC can name a fixed or older
// qemu-system-sparc.
func TestSPARCstation5(t *testing.T) {
	prom := os.Getenv("GOBOOTD_SS5_PROM")
	if prom == "" {
		t.Skip("GOBOOTD_SS5_PROM not set")
	}
	qemu := os.Getenv("GOBOOTD_QEMU_SPARC")
	if qemu == "" {
		var err error
		if qemu, err = exec.LookPath("qemu-system-sparc"); err != nil {
			t.Skip("qemu-system-sparc not found")
		}
	}

	dir := t.TempDir()
	const msg = "gobootd: hello from the network"
	if err := os.WriteFile(filepath.Join(dir, "hello.aout"), helloSPARC(msg), 0o644); err != nil {
		t.Fatal(err)
	}
	bootd, guest := freePort(t), freePort(t)
	conf := fmt.Sprintf(`
resolve {
  ethers = ""
  dns    = false
}
log { file = "bootd.log" }
network "lab" {
  address = "192.168.7.1/24"
  udp     = "%s"
  peers   = ["%s"]
}
service "rarp" {}
service "tftp" {}
host "ss5" {
  mac = "08:00:20:01:02:03"
  ip  = "192.168.7.5"
  file "hello.aout" { name = "*" }   # the PROM asks for C0A80705.SUN4M
}
`, bootd, guest)
	path := filepath.Join(dir, "bootd.hcl")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	done := make(chan error, 1)
	var stderr bytes.Buffer
	go func() { done <- daemon.Run(ctx, path, nil, &stderr) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("bootd: %v\n%s", err, stderr.String())
		}
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(dir, "bootd.log"))
			t.Logf("bootd log:\n%s", log)
		}
	}()

	cmd := exec.CommandContext(ctx, qemu, "-M", "SS-5", "-m", "64", "-bios", prom, "-nographic",
		"-netdev", fmt.Sprintf("dgram,id=n0,local.type=inet,local.host=%s,local.port=%d,remote.type=inet,remote.host=%s,remote.port=%d",
			guest.Addr(), guest.Port(), bootd.Addr(), bootd.Port()),
		"-net", "nic,model=lance,netdev=n0,macaddr=08:00:20:01:02:03")
	cmd.Stdin = strings.NewReader("") // the PROM boots from the network by itself
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	var console strings.Builder
	sc := bufio.NewScanner(out)
	sc.Split(scanLines)
	for sc.Scan() {
		line := strings.ReplaceAll(sc.Text(), "\b", "")
		console.WriteString(line + "\n")
		switch {
		case strings.Contains(line, msg):
			return // booted and ran our program
		case strings.Contains(line, "Wrong packet length"):
			t.Fatalf("the PROM's LANCE loopback test failed: this QEMU pads loopback frames (QEMU 10.2 and later); set GOBOOTD_QEMU_SPARC to a fixed qemu-system-sparc\n%s", console.String())
		case strings.Contains(line, "Instruction Access Exception"),
			strings.Contains(line, "Can't open boot device"),
			strings.Contains(line, "Timeout waiting for ARP/RARP packet"):
			t.Fatalf("boot failed:\n%s", console.String())
		}
	}
	t.Fatalf("QEMU exited or timed out before the boot program ran:\n%s", console.String())
}

// scanLines splits on \r or \n; the PROM's console uses both.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}
