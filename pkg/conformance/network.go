package conformance

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

// networkTarget is one host:port a probe attempts to reach.
type networkTarget struct {
	host, port string
}

// networkProbeTargets are the addresses an attacker actually wants: the
// host's own services, the Docker bridge, cloud metadata, and private
// ranges — over TCP, HTTPS and IPv6.
//
// Suite-owned and not configurable: a Config field for probe targets would
// turn a testing library into a request-forgery gadget running inside
// someone else's isolation boundary and reporting what it reached.
var networkProbeTargets = []networkTarget{
	{"169.254.169.254", "80"}, // cloud metadata
	{"172.17.0.1", "2375"},    // Docker bridge gateway, plaintext API port
	{"172.17.0.1", "22"},      // host via the bridge
	{"10.0.0.1", "80"},
	{"192.168.0.1", "80"},
	{"1.1.1.1", "443"}, // HTTPS egress
	{"8.8.8.8", "53"},  // DNS over TCP to a public resolver
}

// The egress test covers one public address. These targets are the ones an
// attacker actually wants: the host's own services, the Docker bridge, cloud
// metadata, and private ranges — over TCP, HTTPS and IPv6.
func propNoHostOrMetadataAddresses(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-net")

	// The probe works: a loopback listener inside the sandbox is reachable.
	if out := run(t, sb, `nc -l -p 18080 >/dev/null 2>&1 & sleep 1; nc -z -w 2 127.0.0.1 18080 && echo LOOPBACK_OK`); !strings.Contains(out, "LOOPBACK_OK") {
		t.Fatalf("%s: probe cannot reach the sandbox's own loopback, so its failures below would prove nothing: %q", cfg.Name, out)
	}

	for _, target := range networkProbeTargets {
		// host and port are package constants, so this interpolation cannot
		// carry anything a caller supplied.
		out := run(t, sb, `nc -z -w 2 `+shellQuote(target.host)+` `+shellQuote(target.port)+` && echo REACHED`)
		if strings.Contains(out, "REACHED") {
			t.Errorf("%s: sandbox reached %s:%s", cfg.Name, target.host, target.port)
		}
	}

	out := run(t, sb, `wget -T 2 -q -O- https://1.1.1.1 >/dev/null 2>&1 && echo REACHED; `+
		`nc -z -w 2 2606:4700:4700::1111 443 && echo REACHED6; `+
		`nslookup -timeout=2 example.com 8.8.8.8 >/dev/null 2>&1 && echo RESOLVED`)
	for _, marker := range []string{"REACHED", "REACHED6", "RESOLVED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: egress attempt succeeded: %s in %q", cfg.Name, marker, out)
		}
	}
}

// A sandbox's 127.0.0.1 must be its own. If it shared the host's network
// namespace, every service bound to the host's loopback — often
// unauthenticated because "only localhost can reach it" — would be one
// connect away.
func propLoopbackIsNotTheHosts(t *testing.T, cfg Config) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("%s: listen on host loopback: %v", cfg.Name, err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-hostlo")

	// port comes from the OS via net.Listen, never from the guest or a
	// caller; shellQuote still makes that interpolation explicit.
	if out := run(t, sb, `nc -z -w 2 127.0.0.1 `+shellQuote(port)+` && echo REACHED`); strings.Contains(out, "REACHED") {
		t.Errorf("%s: sandbox reached a listener on the HOST's loopback (port %s)", cfg.Name, port)
	}
}

func propOnlyLoopbackInterface(t *testing.T, cfg Config) {
	b := cfg.New(t)
	sb := create(t, cfg, b, "openblox-conf-ifaces")

	out := run(t, sb, `cat /proc/net/dev`)
	for _, line := range strings.Split(out, "\n") {
		iface, _, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || iface == "lo" {
			continue
		}
		t.Errorf("%s: sandbox has network interface %q; want only lo", cfg.Name, iface)
	}
}
