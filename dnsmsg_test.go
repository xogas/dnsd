package main

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	msg := &Message{
		Header:   Header{ID: 0xBEEF, QR: true, Opcode: OpcodeQuery, AA: true, RD: true, RA: true, CD: true},
		Question: []Question{{Name: "www.example.com", Type: TypeA, Class: ClassIN}},
		Answer: []*RR{
			{Name: "www.example.com", Type: TypeA, Class: ClassIN, TTL: 300, Data: AData{Addr: netip.MustParseAddr("192.0.2.1")}},
			{Name: "www.example.com", Type: TypeAAAA, Class: ClassIN, TTL: 300, Data: AAAAData{Addr: netip.MustParseAddr("2001:db8::1")}},
			{Name: "www.example.com", Type: TypeCNAME, Class: ClassIN, TTL: 300, Data: DomainData{Name: "origin.example.com"}},
			{Name: "example.com", Type: TypeNS, Class: ClassIN, TTL: 300, Data: DomainData{Name: "ns1.example.com"}},
			{Name: "example.com", Type: TypeMX, Class: ClassIN, TTL: 300, Data: MXData{Preference: 10, Name: "mail.example.com"}},
			{Name: "example.com", Type: TypeTXT, Class: ClassIN, TTL: 300, Data: TXTData{Strings: []string{"hello world", ""}}},
			{Name: "example.com", Type: TypeSOA, Class: ClassIN, TTL: 300, Data: SOAData{MName: "ns1.example.com", RName: "hostmaster.example.com", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}},
			{Name: "_sip._tcp.example.com", Type: TypeSRV, Class: ClassIN, TTL: 300, Data: SRVData{Priority: 1, Weight: 5, Port: 5060, Name: "sip.example.com"}},
			{Name: "2.0.192.in-addr.arpa", Type: TypePTR, Class: ClassIN, TTL: 300, Data: DomainData{Name: "www.example.com"}},
			{Name: "example.com", Type: Type(65280), Class: ClassIN, TTL: 300, Data: RawData{Bytes: []byte{1, 2, 3, 4}}},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !reflect.DeepEqual(got, msg) {
		t.Fatalf("round trip mismatch:\ngot  %+v\nwant %+v", got, msg)
	}
}

// TestCompression verifies that repeated names are compressed on the wire
// and still decode correctly.
func TestCompression(t *testing.T) {
	msg := &Message{
		Header:   Header{ID: 7, QR: true},
		Question: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
		Answer: []*RR{
			{Name: "www.example.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: DomainData{Name: "example.com"}},
			{Name: "www.example.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: AData{Addr: netip.MustParseAddr("192.0.2.1")}},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !reflect.DeepEqual(got, msg) {
		t.Fatalf("round trip mismatch:\ngot  %+v\nwant %+v", got, msg)
	}
	if len(b) > 90 {
		t.Fatalf("expected compression to keep the message small, got %d bytes", len(b))
	}
}

// TestDecodeCompression builds a message by hand with a compression
// pointer in the RDATA of a CNAME record.
func TestDecodeCompression(t *testing.T) {
	base := &Message{
		Header:   Header{ID: 1, QR: true},
		Question: []Question{{Name: "example.com", Type: TypeCNAME, Class: ClassIN}},
	}
	packed, err := base.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// The question name starts at offset 12. Append an answer record:
	// name "www" + pointer to 12, type CNAME, class IN, TTL 60,
	// rdata pointer to 12 (the question name).
	rr := []byte{
		3, 'w', 'w', 'w', 0xC0, 0x0C,
		0, 5, 0, 1, 0, 0, 0, 60,
		0, 2, 0xC0, 0x0C,
	}
	packed = append(packed, rr...)
	binary.BigEndian.PutUint16(packed[6:8], 1) // ANCOUNT = 1
	got, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answer))
	}
	a := got.Answer[0]
	if a.Name != "www.example.com" {
		t.Errorf("owner = %q, want www.example.com", a.Name)
	}
	if d, ok := a.Data.(DomainData); !ok || d.Name != "example.com" {
		t.Errorf("rdata = %#v, want DomainData{example.com}", a.Data)
	}
}

func TestQuestionCasePreserved(t *testing.T) {
	msg := &Message{
		Header:   Header{ID: 9},
		Question: []Question{{Name: "WWW.Example.COM", Type: TypeA, Class: ClassIN}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got.Question[0].Name != "WWW.Example.COM" {
		t.Errorf("question name = %q, want original case", got.Question[0].Name)
	}
}

func TestExtendedRcode(t *testing.T) {
	msg := &Message{
		Header: Header{ID: 3, QR: true, Rcode: RcodeBadVers},
		Additional: []*RR{{
			Name: ".", Type: TypeOPT,
			Class: Class(1232),
			Data:  OPTData{UDPSize: 1232},
		}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if b[3]&0xF != 0 {
		t.Errorf("header rcode = %d, want 0 (extended rcode goes in the OPT)", b[3]&0xF)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got.Header.Rcode != RcodeBadVers {
		t.Errorf("rcode = %s, want BADVERS", got.Header.Rcode)
	}
}

func TestUnpackErrors(t *testing.T) {
	msg := &Message{Header: Header{ID: 1, QR: true}, Question: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}}}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if _, err := Unpack(b[:10]); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Errorf("short message: err = %v", err)
	}
	if _, err := Unpack(b[:len(b)-2]); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated rdata: err = %v", err)
	}
	// Forward pointer (>= its own position) must be rejected.
	bad := []byte{0, 1, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0F, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := Unpack(bad); err == nil || !strings.Contains(err.Error(), "pointer") {
		t.Errorf("forward pointer: err = %v, want pointer error", err)
	}
	// QDCOUNT says one question but the name never terminates.
	noend := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 2, 'b'}
	if _, err := Unpack(noend); err == nil {
		t.Error("unterminated name: want error")
	}
}

func TestPackLabelTooLong(t *testing.T) {
	msg := &Message{
		Header:   Header{ID: 1},
		Question: []Question{{Name: strings.Repeat("x", 64) + ".com", Type: TypeA, Class: ClassIN}},
	}
	if _, err := msg.Pack(); err == nil {
		t.Error("64-byte label: want error")
	}
}

func TestNameRoundTripRoot(t *testing.T) {
	msg := &Message{
		Header:   Header{ID: 1, QR: true},
		Question: []Question{{Name: ".", Type: TypeNS, Class: ClassIN}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got.Question[0].Name != "." {
		t.Errorf("root name = %q, want \".\"", got.Question[0].Name)
	}
}
