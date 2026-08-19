package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func testZone(t *testing.T, origin, master string) *Zone {
	t.Helper()
	z, err := Parse([]byte(master), origin)
	if err != nil {
		t.Fatalf("parsing zone %s: %v", origin, err)
	}
	return z
}

func startServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s := New(cfg)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = s.udp.Close()
		_ = s.tcp.Close()
	})
	go s.Serve(ctx) //nolint: errcheck
	return s
}

func query(id uint16, name string, typ Type) *Message {
	return &Message{
		Header:   Header{ID: id, Opcode: OpcodeQuery, RD: true},
		Question: []Question{{Name: name, Type: typ, Class: ClassIN}},
	}
}

func queryUDP(t *testing.T, addr string, m *Message) *Message {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close() //nolint: errcheck
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	got, err := Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return got
}

func queryTCP(t *testing.T, addr string, m *Message) *Message {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close() //nolint: errcheck
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out[:2], uint16(len(b)))
	copy(out[2:], b)
	if _, err := conn.Write(out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		t.Fatalf("Read length: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	got, err := Unpack(buf)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return got
}

const exampleZone = `
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1 hostmaster ( 1 3600 600 86400 300 )
@       IN NS ns1
ns1     IN A 192.0.2.1
@       IN A 192.0.2.10
www     IN A 192.0.2.20
www     IN AAAA 2001:db8::20
alias   IN CNAME www
text    IN TXT "a" "b"
`

func TestAuthoritativeUDP(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	resp := queryUDP(t, s.UDPAddr().String(), query(1, "www.example.com", TypeA))
	if !resp.Header.QR || !resp.Header.AA || resp.Header.Rcode != RcodeNoError {
		t.Fatalf("header = %+v", resp.Header)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	if d := resp.Answer[0].Data.(AData); d.Addr.String() != "192.0.2.20" {
		t.Errorf("answer = %s", d.Addr)
	}
	if resp.Question[0].Name != "www.example.com" {
		t.Errorf("question echo = %q", resp.Question[0].Name)
	}
}

func TestNXDomain(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	resp := queryUDP(t, s.UDPAddr().String(), query(2, "nope.example.com", TypeA))
	if resp.Header.Rcode != RcodeNXDomain {
		t.Fatalf("rcode = %s, want NXDOMAIN", resp.Header.Rcode)
	}
	if len(resp.Authority) != 1 || resp.Authority[0].Type != TypeSOA {
		t.Errorf("authority = %+v, want SOA", resp.Authority)
	}
}

func TestNoData(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	resp := queryUDP(t, s.UDPAddr().String(), query(3, "www.example.com", TypeMX))
	if resp.Header.Rcode != RcodeNoError || len(resp.Answer) != 0 {
		t.Fatalf("rcode=%s answers=%d, want NOERROR/NODATA", resp.Header.Rcode, len(resp.Answer))
	}
	if len(resp.Authority) != 1 || resp.Authority[0].Type != TypeSOA {
		t.Errorf("authority = %+v, want SOA", resp.Authority)
	}
}

func TestCNAME(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	resp := queryUDP(t, s.UDPAddr().String(), query(4, "alias.example.com", TypeA))
	if len(resp.Answer) != 1 || resp.Answer[0].Type != TypeCNAME {
		t.Fatalf("answers = %+v, want CNAME", resp.Answer)
	}
}

func TestRefusedAndFormErr(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	addr := s.UDPAddr().String()
	// No matching zone and no upstream: REFUSED.
	if resp := queryUDP(t, addr, query(5, "elsewhere.net", TypeA)); resp.Header.Rcode != RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", resp.Header.Rcode)
	}
	// Garbage packet: FORMERR echoing the ID.
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close() //nolint: errcheck
	_, _ = conn.Write([]byte{0x12, 0x34, 'n', 'o', 't', 'd', 'n', 's'})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	resp, err := Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if resp.Header.ID != 0x1234 || resp.Header.Rcode != RcodeFormErr {
		t.Errorf("formerr response: id=%x rcode=%s", resp.Header.ID, resp.Header.Rcode)
	}
}

func TestNotImp(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	m := &Message{
		Header:   Header{ID: 6, Opcode: OpcodeStatus},
		Question: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
	}
	resp := queryUDP(t, s.UDPAddr().String(), m)
	if resp.Header.Rcode != RcodeNotImp {
		t.Errorf("rcode = %s, want NOTIMP", resp.Header.Rcode)
	}
}

func TestTruncation(t *testing.T) {
	// 60 TXT records of 40 bytes at t0.big.example: about 3.4 KB,
	// well over 512 bytes and within a 4096-byte EDNS(0) budget.
	var sb strings.Builder
	sb.WriteString("$ORIGIN big.example.\n$TTL 300\n@ IN SOA ns1 hostmaster ( 1 2 3 4 5 )\n")
	for range 60 {
		sb.WriteString("t0 IN TXT \"")
		sb.WriteString(strings.Repeat("x", 40))
		sb.WriteString("\"\n")
	}
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "big.example", sb.String())}})
	addr := s.UDPAddr().String()

	// Without EDNS(0) the response must be truncated to 512 bytes.
	resp := queryUDP(t, addr, query(7, "t0.big.example", TypeTXT))
	if !resp.Header.TC {
		t.Error("expected TC bit for a >512 byte response without EDNS(0)")
	}
	if resp.Header.Rcode != RcodeNoError || len(resp.Answer) == 0 {
		t.Errorf("rcode=%s answers=%d", resp.Header.Rcode, len(resp.Answer))
	}

	// With EDNS(0) the full response fits.
	big := query(8, "t0.big.example", TypeTXT)
	big.Additional = []*RR{{
		Name: ".", Type: TypeOPT,
		Class: Class(4096),
		Data:  OPTData{UDPSize: 4096},
	}}
	resp = queryUDP(t, addr, big)
	if resp.Header.TC {
		t.Error("did not expect TC with EDNS(0) size 4096")
	}
	if resp.Header.Rcode != RcodeNoError || len(resp.Answer) != 60 {
		t.Errorf("rcode=%s answers=%d, want 60", resp.Header.Rcode, len(resp.Answer))
	}
}

func TestTCP(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	addr := s.TCPAddr().String()
	// Two queries over one connection (RFC 7766).
	if resp := queryTCP(t, addr, query(9, "www.example.com", TypeA)); len(resp.Answer) != 1 {
		t.Errorf("first query: %+v", resp.Answer)
	}
	if resp := queryTCP(t, addr, query(10, "example.com", TypeA)); len(resp.Answer) != 1 {
		t.Errorf("second query: %+v", resp.Answer)
	}
}

func TestEDNSBadVersion(t *testing.T) {
	s := startServer(t, Config{Zones: []*Zone{testZone(t, "example.com", exampleZone)}})
	m := query(11, "www.example.com", TypeA)
	m.Additional = []*RR{{
		Name: ".", Type: TypeOPT,
		Class: Class(1232),
		Data:  OPTData{UDPSize: 1232, Version: 1},
	}}
	resp := queryUDP(t, s.UDPAddr().String(), m)
	if resp.Header.Rcode != RcodeBadVers {
		t.Errorf("rcode = %s, want BADVERS", resp.Header.Rcode)
	}
	if len(resp.Additional) != 1 || resp.Additional[0].Type != TypeOPT {
		t.Errorf("additional = %+v, want OPT", resp.Additional)
	}
}

func TestGlue(t *testing.T) {
	z := testZone(t, "example.com", `
$ORIGIN example.com.
$TTL 300
@   IN NS ns1
ns1 IN A 192.0.2.53
mail IN MX 10 mail
mail IN A 192.0.2.54
`)
	s := startServer(t, Config{Zones: []*Zone{z}})
	resp := queryUDP(t, s.UDPAddr().String(), query(12, "example.com", TypeNS))
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d", len(resp.Answer))
	}
	if len(resp.Additional) != 1 || resp.Additional[0].Type != TypeA {
		t.Errorf("additional = %+v, want glue A", resp.Additional)
	}
	resp = queryUDP(t, s.UDPAddr().String(), query(13, "mail.example.com", TypeMX))
	if len(resp.Additional) != 1 || resp.Additional[0].Type != TypeA {
		t.Errorf("MX additional = %+v, want glue A", resp.Additional)
	}
}

func TestForwardingAndCache(t *testing.T) {
	// Upstream is authoritative for upstream.example.
	up := startServer(t, Config{Zones: []*Zone{testZone(t, "upstream.example", `
$ORIGIN upstream.example.
$TTL 300
@  IN SOA ns1 hostmaster ( 1 2 3 4 5 )
@  IN NS ns1
ns1 IN A 192.0.2.1
www IN A 198.51.100.7
`)}})
	// Forwarder has no local zones.
	s := startServer(t, Config{Upstream: up.UDPAddr().String(), Timeout: 2 * time.Second})
	addr := s.UDPAddr().String()

	resp := queryUDP(t, addr, query(14, "www.upstream.example", TypeA))
	if resp.Header.Rcode != RcodeNoError || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%s answers=%+v", resp.Header.Rcode, resp.Answer)
	}
	if !resp.Header.RA {
		t.Error("RA bit not set")
	}
	if d := resp.Answer[0].Data.(AData); d.Addr.String() != "198.51.100.7" {
		t.Errorf("answer = %s", d.Addr)
	}

	// Second query hits the cache: the upstream must see only one query.
	resp = queryUDP(t, addr, query(15, "www.upstream.example", TypeA))
	if len(resp.Answer) != 1 {
		t.Fatalf("cached query: %+v", resp.Answer)
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1 (cache miss twice)", got)
	}

	// Negative responses are cached too (RFC 2308).
	_ = queryUDP(t, addr, query(16, "gone.upstream.example", TypeA))
	_ = queryUDP(t, addr, query(17, "gone.upstream.example", TypeA))
	if got := up.queries.Load(); got != 2 {
		t.Errorf("upstream saw %d queries, want 2", got)
	}
	// Uncached, forwarded NXDOMAIN carries the SOA in the authority section.
	resp = queryUDP(t, addr, query(18, "gone2.upstream.example", TypeA))
	if resp.Header.Rcode != RcodeNXDomain || len(resp.Authority) != 1 {
		t.Errorf("forwarded NXDOMAIN: rcode=%s authority=%d", resp.Header.Rcode, len(resp.Authority))
	}
}

func TestForwardServFail(t *testing.T) {
	// Point the forwarder at a port with no listener; UDP reads time out.
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := l.LocalAddr().String()
	_ = l.Close() // free the address; no one listens there now
	s := startServer(t, Config{Upstream: addr, Timeout: 300 * time.Millisecond})
	resp := queryUDP(t, s.UDPAddr().String(), query(19, "any.example", TypeA))
	if resp.Header.Rcode != RcodeServFail {
		t.Errorf("rcode = %s, want SERVFAIL", resp.Header.Rcode)
	}
}

func TestCacheExpiry(t *testing.T) {
	up := startServer(t, Config{Zones: []*Zone{testZone(t, "short.example", `
$ORIGIN short.example.
$TTL 1
@  IN SOA ns1 hostmaster ( 1 2 3 4 5 )
@  IN NS ns1
ns1 IN A 192.0.2.1
www IN A 198.51.100.9
`)}})
	s := startServer(t, Config{Upstream: up.UDPAddr().String(), Timeout: 2 * time.Second})
	addr := s.UDPAddr().String()
	if resp := queryUDP(t, addr, query(20, "www.short.example", TypeA)); len(resp.Answer) != 1 {
		t.Fatalf("first query: %+v", resp.Answer)
	}
	if got := up.queries.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if resp := queryUDP(t, addr, query(21, "www.short.example", TypeA)); len(resp.Answer) != 1 {
		t.Fatalf("second query: %+v", resp.Answer)
	}
	if got := up.queries.Load(); got != 2 {
		t.Errorf("upstream queries = %d, want 2 after expiry", got)
	}
}
