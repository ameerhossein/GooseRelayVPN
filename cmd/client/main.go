// GooseRelayVPN client: SOCKS5 listener that tunnels TCP through Apps Script.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/carrier"
	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/kianmhz/GooseRelayVPN/internal/socks"
)

var version = "dev"

type clientLogWriter struct {
	out      io.Writer
	useColor bool
}

func (w *clientLogWriter) Write(p []byte) (int, error) {
	raw := strings.TrimRight(string(p), "\r\n")
	if raw == "" {
		_, err := w.out.Write(p)
		return len(p), err
	}

	module := "client"
	msg := raw
	if strings.HasPrefix(raw, "[") {
		if idx := strings.Index(raw, "]"); idx > 1 {
			module = strings.ToUpper(strings.TrimSpace(raw[1:idx]))
			msg = strings.TrimSpace(raw[idx+1:])
		}
	}
	module = strings.ToUpper(module)

	level := "INFO"
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "fatal") || strings.Contains(lower, "invalid") || strings.Contains(lower, "required") {
		level = "ERROR"
	} else if strings.Contains(lower, "timeout") || strings.Contains(lower, "non-ok") || strings.Contains(lower, "failed") || strings.Contains(lower, "shutting down") {
		level = "WARN"
	}

	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("%s  %-7s %-7s %s\n", ts, module, level, msg)

	if !w.useColor {
		_, err := io.WriteString(w.out, line)
		return len(p), err
	}

	levelColor := "\x1b[36m" // cyan
	if level == "WARN" {
		levelColor = "\x1b[33m" // yellow
	}
	if level == "ERROR" {
		levelColor = "\x1b[31m" // red
	}
	colored := fmt.Sprintf("%s  \x1b[35m%-7s\x1b[0m %s%-7s\x1b[0m %s\n", ts, module, levelColor, level, msg)
	_, err := io.WriteString(w.out, colored)
	return len(p), err
}

func setupClientLogging() {
	log.SetFlags(0)
	useColor := shouldUseColor(os.Stdout)
	log.SetOutput(&clientLogWriter{out: os.Stdout, useColor: useColor})
}

func shortScriptKey(scriptURL string) string {
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "s" {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
	if len(parts) >= 3 {
		return parts[2]
	}
	return scriptURL
}

func summarizeScriptURLs(scriptURLs []string) string {
	if len(scriptURLs) == 0 {
		return "(none)"
	}
	maxShown := len(scriptURLs)
	if maxShown > 3 {
		maxShown = 3
	}
	parts := make([]string, 0, maxShown)
	for i := 0; i < maxShown; i++ {
		parts = append(parts, shortScriptKey(scriptURLs[i]))
	}
	if len(scriptURLs) > maxShown {
		parts = append(parts, fmt.Sprintf("+%d more", len(scriptURLs)-maxShown))
	}
	return strings.Join(parts, ", ")
}

const gooseBanner = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣄⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣏⣹⣿⠄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠿⠋⢠⣷⣦⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⠛⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⢸⣿⣿⡿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⣠⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠰⢾⣿⣿⣿⡟⠿⠿⣿⣿⠿⠿⠛⠋⣁⣴⣾⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠛⠻⠷⣶⣤⣤⣤⣤⣶⣾⣿⡿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠛⠛⠛⠂⠀⠀⠀⠀
`

func main() {
	fmt.Print(gooseBanner)
	setupClientLogging()

	configPath := flag.String("config", "client_config.json", "path to client config JSON")
	tunMode := flag.Bool("tun", false, "route system TCP traffic through a TUN interface")
	tunDNS := flag.String("tun-dns", "1.1.1.1", "DNS server to use while -tun mode is active")
	flag.Parse()

	if *tunMode {
		ensureTunPrivileges()
	}

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	carrierBindInterface := ""
	if *tunMode {
		defaultRoute, err := currentDefaultRoute()
		if err != nil {
			log.Fatalf("tun: detect default route before carrier startup: %v", err)
		}
		carrierBindInterface = defaultRoute.Dev
		log.Printf("[tun] carrier egress pinned to interface %s", defaultRoute.Dev)
	}
	log.Printf("[client] GooseRelayVPN client starting")
	log.Printf("[client] config loaded from %s", *configPath)
	log.Printf("[client] SOCKS5 proxy: socks5://%s", cfg.ListenAddr)
	if cfg.UseFronting {
		log.Printf("[client] mode: fronting")
		if len(cfg.SNIHosts) == 1 {
			log.Printf("[client] fronting via %s (sni=%s)", cfg.GoogleIP, cfg.SNIHosts[0])
		} else {
			log.Printf("[client] fronting via %s (sni hosts: %s — %d throttle buckets)", cfg.GoogleIP, strings.Join(cfg.SNIHosts, ", "), len(cfg.SNIHosts))
		}
	} else {
		log.Printf("[client] mode: direct relay_urls (fronting disabled)")
	}
	log.Printf("[client] relay endpoints: %d (%s)", len(cfg.ScriptURLs), summarizeScriptURLs(cfg.ScriptURLs))
	if cfg.DebugTiming {
		log.Printf("[client] debug_timing enabled — per-session TTFB and per-poll RTT will be logged")
	}
	if cfg.CoalesceStepMs > 0 {
		log.Printf("[client] uplink coalescing: step=%dms (internal safety cap %dms; bursts of TX collapse into a single poll)", cfg.CoalesceStepMs, cfg.CoalesceMaxMs)
	}
	carr, err := carrier.New(carrier.Config{
		ScriptURLs:         cfg.ScriptURLs,
		ScriptAccounts:     cfg.ScriptAccounts,
		AESKeyHex:          cfg.AESKeyHex,
		DebugTiming:        cfg.DebugTiming,
		ClientVersion:      version,
		CoalesceStep:       time.Duration(cfg.CoalesceStepMs) * time.Millisecond,
		CoalesceMax:        time.Duration(cfg.CoalesceMaxMs) * time.Millisecond,
		IdleSlotsPerBucket: cfg.IdleSlotsPerBucket,
		Fronting: carrier.FrontingConfig{
			GoogleIP:      cfg.GoogleIP,
			SNIHosts:      cfg.SNIHosts,
			BindInterface: carrierBindInterface,
		},
	})
	if err != nil {
		log.Fatalf("carrier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-flight check: one-shot end-to-end probe so users see actionable
	// errors at startup instead of cryptic mid-session failures.
	log.Printf("[client] running pre-flight check (Apps Script reachable, VPS reachable, key matches)…")
	diagCtx, cancelDiag := context.WithTimeout(ctx, 20*time.Second)
	if err := carr.Diagnose(diagCtx); err != nil {
		log.Printf("[client] pre-flight FAILED:")
		for _, line := range strings.Split(err.Error(), "\n") {
			log.Printf("[client]   %s", line)
		}
		log.Printf("[client] continuing anyway — the issue may be transient or recover on its own")
	} else {
		log.Printf("[client] pre-flight OK: relay healthy, AES key matches end-to-end")
	}
	cancelDiag()

	go func() {
		if err := carr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("carrier run: %v", err)
		}
	}()

	factory := socks.SessionFactory(func(target string) *session.Session {
		return carr.NewSession(target)
	})

	go func() {
		log.Printf("[client] ready: local SOCKS5 is listening on %s", cfg.ListenAddr)
		if cfg.SocksUser != "" {
			log.Printf("[client] SOCKS5 auth enabled (RFC 1929 username/password required)")
		}
		if err := socks.Serve(ctx, cfg.ListenAddr, cfg.SocksUser, cfg.SocksPass, cfg.DebugTiming, factory); err != nil {
			log.Fatalf("socks: %v", err)
		}
	}()

	var tunCleanup func()
	if *tunMode {
		opts := tunOptions{
			Name:      defaultTunName,
			CIDR:      defaultTunCIDR,
			DNS:       *tunDNS,
			LogLevel:  defaultTunLogLevel,
			ManageDNS: true,
		}
		cleanup, err := startTunMode(ctx, cfg, opts)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		tunCleanup = cleanup
		log.Printf("[tun] ready: system TCP traffic is routed through %s", defaultTunName)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("[client] shutting down — notifying server of active sessions")
	// Send RSTs for active sessions so the server can release their upstream
	// connections immediately. Bounded so a slow server can't block exit.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	carr.Shutdown(shutdownCtx)
	shutdownCancel()
	if tunCleanup != nil {
		tunCleanup()
	}
	cancel()
}

func ensureTunPrivileges() {
	if os.Geteuid() == 0 {
		return
	}

	sudoCmd := "sudo " + shellQuoteArgs(os.Args)
	if !stdinIsTerminal() {
		log.Fatalf("-tun requires root/CAP_NET_ADMIN. Run: %s", sudoCmd)
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		log.Fatalf("-tun requires root/CAP_NET_ADMIN and sudo was not found. Run as root: %s", shellQuoteArgs(os.Args))
	}

	log.Printf("[tun] re-executing with sudo for TUN, route, and DNS setup")
	args := append([]string{"sudo"}, os.Args...)
	if err := syscall.Exec(sudoPath, args, os.Environ()); err != nil {
		log.Fatalf("sudo exec failed: %v", err)
	}
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func shellQuoteArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" {
			quoted = append(quoted, "''")
			continue
		}
		if strings.IndexFunc(arg, func(r rune) bool { return !isShellSafeRune(r) }) == -1 {
			quoted = append(quoted, arg)
			continue
		}
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", "'\\''")+"'")
	}
	return strings.Join(quoted, " ")
}

func isShellSafeRune(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	return strings.ContainsRune("/-_.=:,+%@~", r)
}
