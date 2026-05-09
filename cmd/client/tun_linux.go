//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
	_ "github.com/xjasonlyu/tun2socks/v2/dns"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	defaultTunName     = "goose0"
	defaultTunCIDR     = "198.18.0.1/15"
	defaultTunLogLevel = "error"
)

type tunOptions struct {
	Name        string
	CIDR        string
	DNS         string
	LogLevel    string
	ManageDNS   bool
	BypassCIDRs []string
}

type defaultRoute struct {
	Via string
	Dev string
}

func startTunMode(ctx context.Context, cfg *config.Client, opts tunOptions) (func(), error) {
	if err := validateTunOptions(opts); err != nil {
		return nil, err
	}
	if err := ensureTunDeviceAvailable(); err != nil {
		return nil, err
	}

	dnsBypassIPs := systemDNSServers()
	bypassIPs, err := resolveBypassIPs(ctx, cfg)
	if err != nil {
		return nil, err
	}
	bypassIPs = append(bypassIPs, dnsBypassIPs...)
	defaultRoute, err := currentDefaultRoute()
	if err != nil {
		return nil, err
	}

	proxyURL := url.URL{Scheme: "socks5", Host: cfg.ListenAddr}
	if cfg.SocksUser != "" {
		proxyURL.User = url.UserPassword(cfg.SocksUser, cfg.SocksPass)
	}

	engine.Insert(&engine.Key{
		Device:                   "tun://" + opts.Name,
		Proxy:                    proxyURL.String(),
		LogLevel:                 opts.LogLevel,
		MTU:                      1500,
		TCPModerateReceiveBuffer: true,
		TCPReceiveBufferSize:     "4MiB",
		TCPSendBufferSize:        "4MiB",
		UDPTimeout:               2 * time.Minute,
	})
	engine.Start()

	cleanup := newTunCleanup(opts.Name)
	cleanup.add(func() {
		engine.Stop()
	})

	if err := run("ip", "addr", "replace", opts.CIDR, "dev", opts.Name); err != nil {
		cleanup.run()
		return nil, err
	}
	if err := run("ip", "link", "set", "dev", opts.Name, "mtu", "1500", "up"); err != nil {
		cleanup.run()
		return nil, err
	}

	for _, ip := range bypassIPs {
		added, err := addBypassIP(defaultRoute, ip)
		if err != nil {
			cleanup.run()
			return nil, err
		}
		if added {
			cleanup.add(func() {
				_ = run("ip", "route", "del", ip.String()+"/32")
			})
		}
	}

	for _, cidr := range append(defaultBypassCIDRs(), opts.BypassCIDRs...) {
		added, err := addBypassCIDR(defaultRoute, cidr)
		if err != nil {
			cleanup.run()
			return nil, err
		}
		if added {
			c := cidr
			cleanup.add(func() {
				_ = run("ip", "route", "del", c)
			})
		}
	}

	if err := run("ip", "route", "replace", "0.0.0.0/1", "dev", opts.Name, "metric", "1"); err != nil {
		cleanup.run()
		return nil, err
	}
	cleanup.add(func() {
		_ = run("ip", "route", "del", "0.0.0.0/1", "dev", opts.Name)
	})

	if err := run("ip", "route", "replace", "128.0.0.0/1", "dev", opts.Name, "metric", "1"); err != nil {
		cleanup.run()
		return nil, err
	}
	cleanup.add(func() {
		_ = run("ip", "route", "del", "128.0.0.0/1", "dev", opts.Name)
	})

	if opts.ManageDNS {
		dnsCleanup, err := setupDNS(opts.Name, opts.DNS)
		if err != nil {
			cleanup.run()
			return nil, err
		}
		cleanup.add(dnsCleanup)
	}

	return cleanup.run, nil
}

func validateTunOptions(opts tunOptions) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`).MatchString(opts.Name) {
		return fmt.Errorf("invalid tun name %q", opts.Name)
	}
	if _, _, err := net.ParseCIDR(opts.CIDR); err != nil {
		return fmt.Errorf("invalid tun CIDR %q: %w", opts.CIDR, err)
	}
	if opts.ManageDNS {
		if _, err := resolvectlDNSEndpoint(opts.DNS); err != nil {
			return err
		}
	}
	switch opts.LogLevel {
	case "debug", "info", "warn", "error", "silent":
	default:
		return fmt.Errorf("invalid tun log level %q", opts.LogLevel)
	}
	for _, cidr := range opts.BypassCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid bypass CIDR %q: %w", cidr, err)
		}
	}
	return nil
}

func systemDNSServers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || !addr.Is4() || addr.IsLoopback() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func resolvectlDNSEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("tun DNS cannot be empty")
	}
	if host, name, ok := strings.Cut(raw, "#"); ok {
		if net.ParseIP(strings.TrimSpace(host)) == nil {
			return "", fmt.Errorf("invalid DNS IP %q", host)
		}
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("DNS-over-TLS server name is empty in %q", raw)
		}
		return strings.TrimSpace(host) + "#" + strings.TrimSpace(name), nil
	}
	if net.ParseIP(raw) == nil {
		return "", fmt.Errorf("invalid DNS IP %q", raw)
	}
	switch raw {
	case "1.1.1.1", "1.0.0.1":
		return raw + "#cloudflare-dns.com", nil
	case "8.8.8.8", "8.8.4.4":
		return raw + "#dns.google", nil
	case "9.9.9.9", "149.112.112.112":
		return raw + "#dns.quad9.net", nil
	default:
		return raw, nil
	}
}

func ensureTunDeviceAvailable() error {
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return nil
	}
	_ = run("modprobe", "tun")
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("/dev/net/tun is unavailable; load the tun kernel module: %w", err)
	}
	return nil
}

func resolveBypassIPs(ctx context.Context, cfg *config.Client) ([]netip.Addr, error) {
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr
	add := func(host string) error {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok || !addr.Is4() {
				return nil
			}
			if _, exists := seen[addr]; !exists {
				seen[addr] = struct{}{}
				out = append(out, addr)
			}
			return nil
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return fmt.Errorf("resolve bypass host %q: %w", host, err)
		}
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip.IP)
			if ok && addr.Is4() {
				if _, exists := seen[addr]; !exists {
					seen[addr] = struct{}{}
					out = append(out, addr)
				}
			}
		}
		return nil
	}

	if cfg.UseFronting {
		if err := add(cfg.GoogleIP); err != nil {
			return nil, err
		}
		return out, nil
	}

	for _, raw := range cfg.ScriptURLs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		if err := add(u.Host); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func currentDefaultRoute() (defaultRoute, error) {
	out, err := output("ip", "-4", "route", "show", "default")
	if err != nil {
		return defaultRoute{}, err
	}
	fields := strings.Fields(out)
	route := defaultRoute{}
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			route.Via = fields[i+1]
		case "dev":
			route.Dev = fields[i+1]
		}
	}
	if route.Dev == "" {
		return defaultRoute{}, errors.New("could not find default route device")
	}
	return route, nil
}

func addBypassIP(route defaultRoute, ip netip.Addr) (bool, error) {
	return addBypassCIDR(route, ip.String()+"/32")
}

func addBypassCIDR(route defaultRoute, cidr string) (bool, error) {
	args := []string{"route", "add", cidr}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev)
	out, err := commandOutput("ip", args...)
	if err == nil {
		return true, nil
	}
	if strings.Contains(out, "File exists") || strings.Contains(out, "RTNETLINK answers: File exists") {
		return false, nil
	}
	return false, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
}

func defaultBypassCIDRs() []string {
	return []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}
}

func setupDNS(tunName, dnsIP string) (func(), error) {
	dnsEndpoint, err := resolvectlDNSEndpoint(dnsIP)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return nil, fmt.Errorf("DNS tunneling requires systemd-resolved/resolvectl so DNS can use TCP/TLS; install/enable it or run with -no-tun-dns")
	}

	if err := run("resolvectl", "dns", tunName, dnsEndpoint); err != nil {
		return nil, err
	}
	if err := run("resolvectl", "domain", tunName, "~."); err != nil {
		return nil, err
	}
	if err := run("resolvectl", "default-route", tunName, "yes"); err != nil {
		return nil, err
	}
	if err := run("resolvectl", "dnsovertls", tunName, "yes"); err != nil {
		return nil, fmt.Errorf("%w; DNS tunneling needs DNS-over-TLS because Goose TUN mode is TCP-only", err)
	}

	return func() {
		_ = run("resolvectl", "revert", tunName)
	}, nil
}

func run(name string, args ...string) error {
	out, err := commandOutput(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	out, err := commandOutput(name, args...)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return out, nil
}

func commandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type tunCleanup struct {
	name string
	fns  []func()
}

func newTunCleanup(name string) *tunCleanup {
	return &tunCleanup{name: name}
}

func (c *tunCleanup) add(fn func()) {
	c.fns = append(c.fns, fn)
}

func (c *tunCleanup) run() {
	for i := len(c.fns) - 1; i >= 0; i-- {
		c.fns[i]()
	}
	if c.name != "" {
		if err := run("ip", "link", "del", "dev", c.name); err != nil {
			if !strings.Contains(err.Error(), "Cannot find device") {
				log.Printf("[tun] cleanup warning: %v", err)
			}
		}
	}
}
