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
//
// This table is not the whole list of what the suite dials. egressProbe, in
// this file, also reaches 1.1.1.1:443 (TLS), [2606:4700:4700::1111]:443 (TCP
// over IPv6) and 8.8.8.8:53 (UDP) — the same three addresses the wget and
// nslookup attempts used before that probe was rewritten, named here so an
// audit of "what does this suite connect to?" finds them from one place.
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
	b := newBackend(t, cfg)
	sb := create(t, cfg, b, cfg.sbName("openblox-conf-net"))

	// The probe works: a loopback listener inside the sandbox is reachable.
	if out := run(t, cfg, sb, `nc -l -p 18080 >/dev/null 2>&1 & sleep 1; nc -z -w 2 127.0.0.1 18080 && echo LOOPBACK_OK`); !strings.Contains(out, "LOOPBACK_OK") {
		t.Fatalf("%s: probe cannot reach the sandbox's own loopback, so its failures below would prove nothing: %q", cfg.Name, out)
	}

	for _, target := range networkProbeTargets {
		// host and port are package constants, so this interpolation cannot
		// carry anything a caller supplied.
		out := run(t, cfg, sb, `nc -z -w 2 `+shellQuote(target.host)+` `+shellQuote(target.port)+` && echo REACHED`)
		if strings.Contains(out, "REACHED") {
			t.Errorf("%s: sandbox reached %s:%s", cfg.Name, target.host, target.port)
		}
	}

	// HTTPS, IPv6 and DNS go through python3 rather than wget and nslookup:
	// the reference image ships neither, so the original probe's attack steps
	// could not run at all there and their absent markers would have read as
	// containment. python3 is in the image, and PYTHON_NET_OK below proves its
	// socket layer works in this sandbox before any absence here is read as
	// evidence of anything.
	out := run(t, cfg, sb, egressProbe)
	if strings.Contains(out, "NO_PYTHON") {
		t.Fatalf("%s: probe requires python3, which the pinned reference image must provide: %q", cfg.Name, out)
	}
	if !strings.Contains(out, "PYTHON_NET_OK") {
		t.Fatalf("%s: the probe's own socket layer does not work, so the absences below would prove nothing: %q", cfg.Name, out)
	}
	for _, marker := range []string{"REACHED_TLS", "REACHED6", "RESOLVED"} {
		if strings.Contains(out, marker) {
			t.Errorf("%s: egress attempt succeeded: %s in %q", cfg.Name, marker, out)
		}
	}
}

// egressProbe attempts HTTPS to a public address, a TCP connect over IPv6, and
// a DNS query straight to a public resolver — and, first, a connect to a
// listener it starts itself, so a run where every attempt fails for want of a
// working socket layer is distinguishable from one where the sandbox contained
// them.
const egressProbe = `
command -v python3 >/dev/null 2>&1 || echo NO_PYTHON
python3 - <<'PY' 2>/dev/null
import socket
import ssl

# Positive control, covering every socket family the three attempts below
# use: IPv4 TCP end to end, IPv6 support compiled in, and a UDP socket that
# constructs. A python without IPv6, or one where SOCK_DGRAM fails, would
# otherwise make REACHED6 and RESOLVED silently vacuous under a control that
# still passed.
try:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    c = socket.create_connection(srv.getsockname(), timeout=2)
    c.close()
    srv.close()
    if not socket.has_ipv6:
        raise OSError("no IPv6 support")
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()
    print("PYTHON_NET_OK")
except Exception:
    pass

# Verification is off on purpose and is not a weakness here: this probe is
# measuring whether the sandbox can reach 1.1.1.1 at all, and a certificate
# check against a bare IP would abort the attempt for a reason that has
# nothing to do with containment — the exact vacuity this suite is closing.
# Nothing is sent over this socket and nothing read from it is trusted.
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("1.1.1.1", 443), timeout=2) as raw:
        with ctx.wrap_socket(raw) as tls:
            tls.send(b"HEAD / HTTP/1.0\r\n\r\n")
            print("REACHED_TLS")
except Exception:
    pass

try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("2606:4700:4700::1111", 443))
    s.close()
    print("REACHED6")
except Exception:
    pass

# A DNS query addressed at a public resolver, so a sandbox that runs a
# resolver of its own cannot make this look contained: A example.com IN.
query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(query, ("8.8.8.8", 53))
    data, _ = s.recvfrom(512)
    s.close()
    if len(data) > 12:
        print("RESOLVED")
except Exception:
    pass
PY
`

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

	b := newBackend(t, cfg)
	sb := create(t, cfg, b, cfg.sbName("openblox-conf-hostlo"))

	// port comes from the OS via net.Listen, never from the guest or a
	// caller; shellQuote still makes that interpolation explicit.
	if out := run(t, cfg, sb, `nc -z -w 2 127.0.0.1 `+shellQuote(port)+` && echo REACHED`); strings.Contains(out, "REACHED") {
		t.Errorf("%s: sandbox reached a listener on the HOST's loopback (port %s)", cfg.Name, port)
	}
}

func propOnlyLoopbackInterface(t *testing.T, cfg Config) {
	b := newBackend(t, cfg)
	sb := create(t, cfg, b, cfg.sbName("openblox-conf-ifaces"))

	// Fail closed. strings.Split("", "\n") is [""], so an empty read would run
	// the loop zero times and the property would pass having verified nothing
	// — a missing cat, an unreadable /proc/net/dev, or a backend that dropped
	// the output would all read as "only lo". Requiring the loopback line to
	// actually be there establishes the probe produced the table it is about
	// to reason over.
	out := run(t, cfg, sb, `cat /proc/net/dev`)
	sawLoopback := false
	for _, line := range strings.Split(out, "\n") {
		iface, _, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		if iface == "lo" {
			sawLoopback = true
			continue
		}
		t.Errorf("%s: sandbox has network interface %q; want only lo", cfg.Name, iface)
	}
	if !sawLoopback {
		t.Fatalf("%s: the probe read no lo interface out of /proc/net/dev, so it has not read the interface table at all: %q", cfg.Name, out)
	}
}
