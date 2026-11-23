// Package httpd serves the files and exports of a host read-only over
// HTTP/1.1, for installers that fetch their sets or archives by URL, such
// as NetBSD's sysinst and Solaris flash archives. Paths are the ones NFS
// clients mount, as with WebNFS; see package pubfs.
//
// Clients are identified by their IP address. Only GET and HEAD are
// answered, ranges included; directories are listed, and there are no
// index pages or CGI programs.
package httpd

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/proto/pubfs"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.HTTP, func() daemon.Service { return &Server{} }) }

// Options are the settings in the http service block.
type Options struct {
	// Port is the port to listen on. Default 80.
	Port int `hcl:"port,optional"`
}

// Server serves files over HTTP.
type Server struct {
	opts Options
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.Port <= 0 {
		s.opts.Port = 80
	}
	if len(env.Networks) == 0 {
		return errors.New("no network")
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, n := range env.Networks {
		l, err := n.IP.ListenTCP(uint16(s.opts.Port))
		if err != nil {
			cancel(nil)
			return fmt.Errorf("network %s: %w", n.Name(), err)
		}
		env.Log.Info("listening", "network", n.Name(), "addr", netip.AddrPortFrom(n.Addr().Addr(), uint16(s.opts.Port)).String())
		srv := &http.Server{
			Handler:           &handler{env: env, n: n},
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(env.Log.Handler(), slog.LevelDebug),
		}
		stop := context.AfterFunc(ctx, func() { srv.Close() })
		defer stop()
		wg.Go(func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				cancel(fmt.Errorf("network %s: %w", n.Name(), err))
			}
		})
	}
	<-ctx.Done()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

type handler struct {
	env *daemon.Env
	n   *netif.Network
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "bootd")
	ip := clientIP(r.RemoteAddr)
	log := h.env.Log.With("network", h.n.Name(), "client", ip.String())
	p := pubfs.Clean(r.URL.Path)
	denied := func(who string, code int, reason string) {
		log.Info(fmt.Sprintf("http request from %s for %s denied (%s)", who, p, reason), "method", r.Method)
		http.Error(w, http.StatusText(code), code)
	}

	host, err := h.env.Inventory().ByIP(ip)
	if err == nil {
		err = host.Allows(service.HTTP)
	}
	if err != nil {
		who := ip.String()
		if host != nil {
			who = host.Name
		}
		denied(who, http.StatusForbidden, err.Error())
		return
	}
	log = log.With("host", host.Name)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		denied(host.Name, http.StatusMethodNotAllowed, r.Method+" not supported, the server is read only")
		return
	}

	t := pubfs.New(host, service.HTTP)
	fi, err := t.Stat(p)
	if err != nil {
		code, reason := status(err)
		denied(host.Name, code, reason)
		return
	}
	if fi.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			u := url.URL{Path: p + "/", RawQuery: r.URL.RawQuery}
			if p == "/" {
				u.Path = "/"
			}
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		}
		list, err := t.ReadDir(p)
		if err != nil {
			code, reason := status(err)
			denied(host.Name, code, reason)
			return
		}
		log.Debug(fmt.Sprintf("http listing of %s for %s", p, host.Name))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		writeIndex(w, p, list)
		return
	}
	f, err := t.Open(p)
	if err != nil {
		code, reason := status(err)
		denied(host.Name, code, reason)
		return
	}
	defer f.Close()
	attrs := []any{"bytes", f.Info.Size(), "method", r.Method}
	if rg := r.Header.Get("Range"); rg != "" {
		attrs = append(attrs, "range", rg)
	}
	log.Info(fmt.Sprintf("http request from %s for %s: sending %s", host.Name, p, f.Source), attrs...)
	http.ServeContent(w, r, f.Info.Name(), f.Info.ModTime(), f)
}

// clientIP is the address of the remote end of a connection.
func clientIP(remote string) netip.Addr {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		host, _, _ := net.SplitHostPort(remote)
		a, _ := netip.ParseAddr(host)
		return a.Unmap()
	}
	return ap.Addr().Unmap()
}

// status is the HTTP status and log reason for a pubfs error.
func status(err error) (int, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound, "not found"
	case pubfs.IsNotDir(err):
		return http.StatusNotFound, "not a directory"
	}
	return http.StatusForbidden, err.Error()
}

// writeIndex lists a directory, in the style of a web server's index.
func writeIndex(w http.ResponseWriter, p string, list []fs.FileInfo) {
	title := html.EscapeString("Index of " + p)
	fmt.Fprintf(w, "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>%s</title></head>\n<body><h1>%s</h1>\n<pre>\n", title, title)
	if p != "/" {
		fmt.Fprintln(w, `<a href="../">../</a>`)
	}
	for _, fi := range list {
		name := fi.Name()
		size := fmt.Sprint(fi.Size())
		if fi.IsDir() {
			name += "/"
			size = "-"
		}
		href := (&url.URL{Path: name}).EscapedPath()
		if strings.Contains(strings.SplitN(name, "/", 2)[0], ":") {
			href = "./" + href // not a URL scheme
		}
		pad := max(1, 50-len(name))
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>%s%s %20s\n", html.EscapeString(href), html.EscapeString(name),
			strings.Repeat(" ", pad), fi.ModTime().UTC().Format("02-Jan-2006 15:04"), size)
	}
	fmt.Fprintln(w, "</pre></body></html>")
}
