package main

import (
	"net/netip"
	"strings"
	"testing"
)

const master = `
; comment line
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1 hostmaster (
            2024010101 3600 600 86400 300 )
@       IN NS ns1
ns1     IN A 192.0.2.1
www     IN A 192.0.2.2
www     IN AAAA 2001:db8::2
mail    IN MX 10 mail
alias   IN CNAME www
text    IN TXT "hello world" "second string"
_sip._tcp IN SRV 1 5 5060 sip
sip     IN A 192.0.2.40
`

func parseMaster(t *testing.T, data, origin string) *Zone {
	t.Helper()
	z, err := Parse([]byte(data), origin)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return z
}

func TestParseAndLookup(t *testing.T) {
	z := parseMaster(t, master, "example.com")
	if z.Origin != "example.com" {
		t.Errorf("origin = %q, want example.com", z.Origin)
	}
	if z.SOA() == nil {
		t.Fatal("zone has no SOA")
	}

	res := z.Lookup("www.example.com", TypeA, ClassIN)
	if res.NXDomain || len(res.Records) != 1 {
		t.Fatalf("www A: %+v", res)
	}
	if d := res.Records[0].Data.(AData); d.Addr != netip.MustParseAddr("192.0.2.2") {
		t.Errorf("www A = %s", d.Addr)
	}

	// NXDOMAIN for a name with no records at all.
	if res := z.Lookup("nope.example.com", TypeA, ClassIN); !res.NXDomain {
		t.Error("nope.example.com should be NXDOMAIN")
	}

	// NODATA: the name exists but not with the requested type.
	res = z.Lookup("www.example.com", TypeMX, ClassIN)
	if res.NXDomain || len(res.Records) != 0 {
		t.Errorf("www MX: want NODATA, got %+v", res)
	}

	// CNAME rule (RFC 1034 section 3.6.2).
	res = z.Lookup("alias.example.com", TypeA, ClassIN)
	if len(res.Records) != 1 || res.Records[0].Type != TypeCNAME {
		t.Errorf("alias A: want CNAME, got %+v", res)
	}

	// Case-insensitive lookup (RFC 4343).
	if res := z.Lookup("WWW.EXAMPLE.COM", TypeA, ClassIN); len(res.Records) != 1 {
		t.Error("uppercase lookup failed")
	}

	// MX relative target resolved against the origin.
	res = z.Lookup("mail.example.com", TypeMX, ClassIN)
	if d := res.Records[0].Data.(MXData); d.Name != "mail.example.com" {
		t.Errorf("MX target = %q", d.Name)
	}

	// TXT strings.
	res = z.Lookup("text.example.com", TypeTXT, ClassIN)
	if d := res.Records[0].Data.(TXTData); len(d.Strings) != 2 || d.Strings[0] != "hello world" {
		t.Errorf("TXT = %+v", d)
	}

	// SRV fields.
	res = z.Lookup("_sip._tcp.example.com", TypeSRV, ClassIN)
	srv := res.Records[0].Data.(SRVData)
	if srv.Priority != 1 || srv.Weight != 5 || srv.Port != 5060 || srv.Name != "sip.example.com" {
		t.Errorf("SRV = %+v", srv)
	}

	// ANY returns all records at the name.
	res = z.Lookup("www.example.com", TypeANY, ClassIN)
	if len(res.Records) != 2 {
		t.Errorf("ANY: got %d records, want 2", len(res.Records))
	}

	// Glue records.
	glue := z.Additional("ns1.example.com")
	if len(glue) != 1 || glue[0].Type != TypeA {
		t.Errorf("glue = %+v", glue)
	}
}

func TestParseBlankOwnerAndDefaults(t *testing.T) {
	data := `
$ORIGIN example.org.
$TTL 60
@ IN A 192.0.2.9
  IN NS ns1
ns1 IN A 192.0.2.10
`
	z := parseMaster(t, data, "example.org")
	if res := z.Lookup("example.org", TypeNS, ClassIN); len(res.Records) != 1 {
		t.Errorf("blank-owner NS: %+v", res)
	}
	if res := z.Lookup("example.org", TypeA, ClassIN); res.Records[0].TTL != 60 {
		t.Errorf("$TTL not applied: %d", res.Records[0].TTL)
	}
	if res := z.Lookup("ns1.example.org", TypeA, ClassIN); res.Records[0].TTL != 60 {
		t.Errorf("record TTL = %d, want 60", res.Records[0].TTL)
	}
}

func TestParseDefaultTTL(t *testing.T) {
	data := "$ORIGIN x.test.\n@ IN A 192.0.2.1\n"
	z := parseMaster(t, data, "x.test")
	if res := z.Lookup("x.test", TypeA, ClassIN); res.Records[0].TTL != defaultTTL {
		t.Errorf("default TTL = %d, want %d", res.Records[0].TTL, defaultTTL)
	}
}

func TestParseRootZone(t *testing.T) {
	data := "com. IN NS a.gtld-servers.net.\n"
	z := parseMaster(t, data, ".")
	if z.Origin != "." {
		t.Errorf("origin = %q", z.Origin)
	}
	if res := z.Lookup("com", TypeNS, ClassIN); len(res.Records) != 1 {
		t.Errorf("root zone lookup: %+v", res)
	}
}

func TestParseOriginDirective(t *testing.T) {
	data := `
$ORIGIN sub.example.com.
www IN A 192.0.2.1
$ORIGIN example.com.
www IN A 192.0.2.2
`
	z := parseMaster(t, data, "fallback.example")
	if z.Origin != "example.com" {
		t.Errorf("final origin = %q, want example.com", z.Origin)
	}
	if res := z.Lookup("www.sub.example.com", TypeA, ClassIN); len(res.Records) != 1 {
		t.Errorf("www.sub.example.com: %+v", res)
	}
	if res := z.Lookup("www.example.com", TypeA, ClassIN); len(res.Records) != 1 {
		t.Errorf("www.example.com: %+v", res)
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"bad ip", "$ORIGIN x.test.\n@ IN A 999.0.0.1\n", "invalid IPv4"},
		{"unknown type", "$ORIGIN x.test.\n@ IN WTF 1 2\n", "unknown record type"},
		{"unbalanced paren", "$ORIGIN x.test.\n@ IN SOA a b ( 1 2 3 4 5\n", "unbalanced"},
		{"unterminated quote", "$ORIGIN x.test.\n@ IN TXT \"oops\n", "unterminated"},
		{"missing type", "$ORIGIN x.test.\n@ IN\n", "missing record type"},
		{"unknown directive", "$FOO bar\n", "unknown directive"},
		{"outside zone", "other.net. IN A 192.0.2.1\n", "outside zone"},
		{"bad mx", "$ORIGIN x.test.\n@ IN MX abc mail\n", "invalid MX preference"},
	} {
		if _, err := Parse([]byte(tc.data), "x.test"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
}
func TestReverseZone(t *testing.T) {
	z := parseMaster(t, `
$ORIGIN 2.0.0.192.in-addr.arpa.
$TTL 3600
2.2.0.0.192.in-addr.arpa. IN PTR www.example.com.
`, "2.0.0.192.in-addr.arpa")
	res := z.Lookup("2.2.0.0.192.in-addr.arpa", TypePTR, ClassIN)
	if len(res.Records) != 1 {
		t.Fatalf("PTR lookup failed: %+v", res)
	}
	if d := res.Records[0].Data.(DomainData); d.Name != "www.example.com" {
		t.Errorf("PTR target = %q", d.Name)
	}
}
