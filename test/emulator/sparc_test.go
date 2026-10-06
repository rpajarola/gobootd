// Package emulator boots emulated machines with their real boot PROMs
// against bootd. PROM images are not part of the repository; tests are
// skipped unless their image is given in the environment.
package emulator

import (
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
	_ "github.com/rpajarola/gobootd/internal/proto/bootparam"
	_ "github.com/rpajarola/gobootd/internal/proto/nfs"
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

// local returns the file named by the environment variable env, or the
// file at path (relative to this directory) if it exists, or "".
func local(env, path string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if abs, err := filepath.Abs(path); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
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
// The PROM image is roms/ss5.bin or GOBOOTD_SS5_PROM.
//
// QEMU 10.2 and later pad loopback frames, which fails the PROM's LANCE
// loopback self-test. The test uses bin/qemu-system-sparc (a patched build)
// or GOBOOTD_QEMU_SPARC if there is one, and qemu-system-sparc from PATH
// otherwise.
func TestSPARCstation5(t *testing.T) {
	prom, qemu := ss5(t)
	dir := t.TempDir()
	const msg = "gobootd: hello from the network"
	if err := os.WriteFile(filepath.Join(dir, "hello.aout"), helloSPARC(msg), 0o644); err != nil {
		t.Fatal(err)
	}
	bootSS5(t, prom, qemu, dir, 3*time.Minute, `
service "rarp" {}
service "tftp" {}
host "ss5" {
  mac = "08:00:20:01:02:03"
  ip  = "192.168.7.5"
  file "hello.aout" { name = "*" }   # the PROM asks for C0A80705.SUN4M
}
`, msg)
}

// TestNetBSDSparc netboots NetBSD's installer on the SS-5 with every
// protocol of a diskless SPARC: the PROM loads boot.net with RARP and
// TFTP, boot.net and the kernel find their root with RARP and bootparam,
// and read it over NFS. Run fetch-netbsd.sh first.
//
// QEMU's SS-5 needs the bpp change in qemu-sparc.patch, or
// NetBSD panics attaching the parallel port.
func TestNetBSDSparc(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about two minutes")
	}
	prom, qemu := ss5(t)
	dir, err := filepath.Abs("netbsd")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root", "netbsd")); err != nil {
		t.Skip("no NetBSD netboot files: run fetch-netbsd.sh")
	}
	// The kernel first waits about 30 seconds for DHCP, which bootd
	// does not answer yet.
	bootSS5(t, prom, qemu, dir, 6*time.Minute, `
service "rarp" {}
service "tftp" {}
service "bootparam" { server_name = "bootd" }
service "nfs" {}
host "ss5" {
  mac = "08:00:20:01:02:03"
  ip  = "192.168.7.5"
  file "boot.net" { name = "*" }
  export "root" {
    path        = "root"
    spec        = "root.mtree"
    export_path = "/ss5/root"   # NetBSD keeps server:path in 90 bytes
  }
  export "swap" {
    path        = "swap"
    export_path = "/ss5/swap"
  }
}
`, "Terminal type?", "cannot mount root", "Cannot load", "panic:", "db>")
}

// ss5 returns the SS-5 PROM image and QEMU, or skips the test.
func ss5(t *testing.T) (prom, qemu string) {
	prom = local("GOBOOTD_SS5_PROM", "roms/ss5.bin")
	if prom == "" {
		t.Skip("no PROM image: put it in roms/ss5.bin or set GOBOOTD_SS5_PROM")
	}
	qemu = local("GOBOOTD_QEMU_SPARC", "bin/qemu-system-sparc")
	if qemu == "" {
		var err error
		if qemu, err = exec.LookPath("qemu-system-sparc"); err != nil {
			t.Skip("qemu-system-sparc not found")
		}
	}
	return prom, qemu
}

// bootSS5 runs bootd in dir with the network block and the given services
// and hosts, boots the SS-5 from it, and waits for success on the console.
// Any of fail on the console fails the test.
func bootSS5(t *testing.T, prom, qemu, dir string, timeout time.Duration, hosts, success string, fail ...string) {
	t.Helper()
	bootd, guest := freePort(t), freePort(t)
	logPath := filepath.Join(t.TempDir(), "bootd.log")
	conf := fmt.Sprintf(`
root = "%s"
resolve {
  ethers = ""
  dns    = false
}
log { file = "%s" }
network "lab" {
  address = "192.168.7.1/24"
  udp     = "%s"
  peers   = ["%s"]
}
`, dir, logPath, bootd, guest) + hosts
	confDir := t.TempDir()
	path := filepath.Join(confDir, "bootd.hcl")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
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
			log, _ := os.ReadFile(logPath)
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

	fail = append(fail, "Instruction Access Exception", "Can't open boot device", "Timeout waiting for ARP/RARP packet")
	// Read the console as it comes: prompts do not end in a newline.
	chunks := make(chan []byte)
	go func() {
		defer close(chunks)
		buf := make([]byte, 4096)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				chunks <- bytes.Clone(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	var console strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case b, ok := <-chunks:
			if !ok {
				t.Fatalf("QEMU exited before %q:\n%s", success, console.String())
			}
			console.Write(bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\b"), nil), []byte("\x00"), nil))
			text := console.String()
			if strings.Contains(text, success) {
				return
			}
			if strings.Contains(text, "Wrong packet length") {
				t.Fatalf("the PROM's LANCE loopback test failed: %s pads loopback frames (QEMU 10.2 and later); see README.md for a patched build in bin/\n%s", qemu, text)
			}
			for _, f := range fail {
				if strings.Contains(text, f) {
					t.Fatalf("boot failed (%s):\n%s", f, text)
				}
			}
		case <-deadline:
			t.Fatalf("timed out after %v waiting for %q:\n%s", timeout, success, console.String())
		}
	}
}
