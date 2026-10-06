// Command bootd is a boot server for many network boot protocols, configured
// from a single file.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/daemon"

	// Protocols register themselves with the daemon.
	_ "github.com/rpajarola/gobootd/internal/proto/bootparam"
	_ "github.com/rpajarola/gobootd/internal/proto/nd"
	_ "github.com/rpajarola/gobootd/internal/proto/nfs"
	_ "github.com/rpajarola/gobootd/internal/proto/rarp"
	_ "github.com/rpajarola/gobootd/internal/proto/rmp"
	_ "github.com/rpajarola/gobootd/internal/proto/tftp"
)

const usage = `usage:
  bootd [run] [-c config]                        run the boot server
  bootd check [-c config] [-q]                   validate the configuration and show what is served
  bootd explain [-c config] <client> [service [file]]
                                                 show how a request from client would be handled;
                                                 client is a host name, MAC or IP address
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("bootd "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	path := fs.String("c", config.DefaultPath, "configuration file")
	quiet := false
	if cmd == "check" {
		fs.BoolVar(&quiet, "q", false, "only print problems")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch cmd {
	case "run":
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		return runDaemon(*path, stderr)
	case "check":
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		return check(*path, quiet, stdout, stderr)
	case "explain":
		if fs.NArg() < 1 || fs.NArg() > 3 {
			fs.Usage()
			return 2
		}
		return explain(*path, fs.Args(), stdout, stderr)
	case "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "bootd: unknown command %q\n", cmd)
	fs.Usage()
	return 2
}

func runDaemon(path string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	reload := make(chan struct{})
	go func() {
		for range hup {
			reload <- struct{}{}
		}
	}()
	if err := daemon.Run(ctx, path, reload, stderr); err != nil {
		fmt.Fprintf(stderr, "bootd: %v\n", err)
		return 1
	}
	return 0
}
