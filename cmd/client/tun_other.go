//go:build !linux

package main

import (
	"context"
	"fmt"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
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

func startTunMode(context.Context, *config.Client, tunOptions) (func(), error) {
	return nil, fmt.Errorf("-tun is currently implemented only on Linux")
}
