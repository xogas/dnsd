package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Zone is an authoritative zone: records sharing a common origin (RFC 1034 4.3.1).
type Zone struct {
	Origin  string // canonical origin, e.g. "example.com"; "." for the root zone
	records map[string][]*RR
	soa     *RR // first SOA record, used in negative answers
}

func newZone(origin string) *Zone {
	return &Zone{
		Origin:  CanonicalName(origin),
		records: make(map[string][]*RR),
	}
}

// LoadFile reads the master file at path; the initial origin is the file name
// without its extension, overridable by $ORIGIN (see Parse).
func LoadFile(path string) (*Zone, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading zone file %s: %w", path, err)
	}
	origin := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if origin == "" {
		origin = "."
	}
	z, err := Parse(data, origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone file %s: %w", path, err)
	}
	return z, nil
}

// Parse parses a master file (RFC 1035 5.1); origin is the initial origin,
// and the zone origin tracks the last $ORIGIN directive.
func Parse(data []byte, origin string) (*Zone, error) {
	z := newZone(origin)
	p := &parser{zone: z, origin: z.Origin}
	if err := p.parse(data); err != nil {
		return nil, err
	}
	return z, nil
}

// Add inserts rr into the zone; the owner must be the origin or a subdomain.
func (z *Zone) Add(rr *RR) error {
	name := CanonicalName(rr.Name)
	if !validName(name) {
		return fmt.Errorf("invalid owner name %q", rr.Name)
	}
	if z.Origin != "." {
		if name != z.Origin && !strings.HasSuffix(name, "."+z.Origin) {
			return fmt.Errorf("record %s is outside zone %s", name, z.Origin)
		}
	}
	c := *rr // the zone owns its records
	rr = &c
	z.records[name] = append(z.records[name], rr)
	if rr.Type == TypeSOA && z.soa == nil {
		z.soa = rr
	}
	return nil
}

// Result is the outcome of a zone lookup.
type Result struct {
	Records  []*RR
	NXDomain bool // the name does not exist in the zone
}

// Lookup resolves name/type per RFC 1034 4.3.2: exact match, then CNAME
// (RFC 1034 3.6.2). An empty result with NXDomain false is NODATA.
func (z *Zone) Lookup(name string, typ Type, class Class) Result {
	key := CanonicalName(name)
	rrs := z.records[key]
	if len(rrs) == 0 {
		return Result{NXDomain: true}
	}
	if typ == TypeANY {
		return Result{Records: rrs}
	}
	var match []*RR
	for _, rr := range rrs {
		if rr.Type == typ && (class == ClassANY || rr.Class == class) {
			match = append(match, rr)
		}
	}
	if len(match) > 0 {
		return Result{Records: match}
	}
	for _, rr := range rrs {
		if rr.Type == TypeCNAME {
			return Result{Records: []*RR{rr}}
		}
	}
	return Result{}
}

// SOA returns the zone's SOA, put in negative responses (RFC 2308), or nil.
func (z *Zone) SOA() *RR { return z.soa }

// Additional returns A/AAAA glue for name, for the additional section
// (RFC 1035 4.3.2).
func (z *Zone) Additional(name string) []*RR {
	key := CanonicalName(name)
	var out []*RR
	for _, rr := range z.records[key] {
		if rr.Type == TypeA || rr.Type == TypeAAAA {
			out = append(out, rr)
		}
	}
	return out
}

// validName checks DNS syntax: labels of 1-63 bytes, at most 255 bytes total
// (RFC 1035 2.3.4).
func validName(name string) bool {
	if name == "." {
		return true
	}
	if name == "" || len(name) > 255 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

// defaultTTL applies to records with no explicit TTL and no $TTL directive.
const defaultTTL = 3600

type token struct {
	text string
	line int
}

// parser walks the tokens of a master file, applying directives and records.
type parser struct {
	zone      *Zone
	origin    string // current origin for relative names
	ttl       uint32
	ttlSet    bool
	prevOwner string // owner of the previous record, for blank-owner lines
}

// lex splits a master file into tokens (RFC 1035 5.1): comments (';' to end
// of line), quoted strings, parentheses and backslash escapes.
func lex(data []byte) ([]token, error) {
	var toks []token
	line := 1
	for i := 0; i < len(data); {
		switch c := data[i]; c {
		case '\n':
			line++
			i++
		case ' ', '\t', '\r':
			i++
		case ';': // comment to end of line
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case '(', ')':
			toks = append(toks, token{string(c), line})
			i++
		case '"': // quoted string, may contain spaces and ';'
			i++
			var sb strings.Builder
			closed := false
			for i < len(data) {
				if data[i] == '"' {
					i++
					closed = true
					break
				}
				if data[i] == '\\' && i+1 < len(data) {
					i++
				}
				sb.WriteByte(data[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("zone: line %d: unterminated quoted string", line)
			}
			toks = append(toks, token{sb.String(), line})
		default:
			var sb strings.Builder
			for i < len(data) {
				c := data[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
					c == ';' || c == '(' || c == ')' || c == '"' {
					break
				}
				if c == '\\' && i+1 < len(data) {
					i++ // escape the next character
				}
				sb.WriteByte(c)
				i++
			}
			toks = append(toks, token{sb.String(), line})
		}
	}
	return toks, nil
}

func (p *parser) parse(data []byte) error {
	toks, err := lex(data)
	if err != nil {
		return err
	}
	// Group tokens into logical records: one per starting line, with
	// continuation lines included while parentheses are open.
	var groups [][]token
	var cur []token
	startLine := -1
	depth := 0
	for _, t := range toks {
		// A new physical line starts a new logical record, unless a
		// parenthesis is still open (RFC 1035 section 5.1).
		if startLine >= 0 && depth == 0 && t.line != startLine {
			groups = append(groups, cur)
			cur = nil
			startLine = -1
		}
		if startLine < 0 {
			startLine = t.line
		}
		cur = append(cur, t)
		if t.text == "(" {
			depth++
		}
		if t.text == ")" {
			depth--
			if depth < 0 {
				return fmt.Errorf("zone: line %d: unbalanced ')'", t.line)
			}
		}
	}
	if len(cur) > 0 {
		if depth != 0 {
			return fmt.Errorf("zone: line %d: unbalanced '('", toks[len(toks)-1].line)
		}
		groups = append(groups, cur)
	}
	for _, g := range groups {
		if err := p.group(g); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) group(g []token) error {
	if len(g) == 0 {
		return nil
	}
	if strings.HasPrefix(g[0].text, "$") {
		return p.directive(g)
	}
	return p.record(g)
}

func (p *parser) directive(g []token) error {
	switch g[0].text {
	case "$ORIGIN":
		if len(g) != 2 {
			return fmt.Errorf("zone: line %d: $ORIGIN takes exactly one argument", g[0].line)
		}
		origin, err := p.domain(g[1].text)
		if err != nil {
			return err
		}
		p.origin = origin
		p.zone.Origin = origin
		return nil
	case "$TTL":
		if len(g) != 2 {
			return fmt.Errorf("zone: line %d: $TTL takes exactly one argument", g[0].line)
		}
		v, err := strconv.ParseUint(g[1].text, 10, 32)
		if err != nil {
			return fmt.Errorf("zone: line %d: invalid $TTL %q", g[1].line, g[1].text)
		}
		p.ttl = uint32(v)
		p.ttlSet = true
		return nil
	default:
		return fmt.Errorf("zone: line %d: unknown directive %s", g[0].line, g[0].text)
	}
}

// domain resolves a master file name (RFC 1035 5.1): "@" is the origin, no
// trailing dot means relative to it, a trailing dot marks an absolute name.
func (p *parser) domain(s string) (string, error) {
	if s == "@" {
		return p.origin, nil
	}
	name := strings.ToLower(s)
	if strings.HasSuffix(name, ".") {
		name = strings.TrimRight(name, ".")
		if name == "" {
			return ".", nil
		}
	} else if p.origin != "." {
		name += "." + p.origin
	}
	if !validName(name) {
		return "", fmt.Errorf("invalid domain name %q", s)
	}
	return name, nil
}

func (p *parser) record(g []token) error {
	// Parentheses only group continuation lines; strip them.
	toks := make([]token, 0, len(g))
	for _, t := range g {
		if t.text != "(" && t.text != ")" {
			toks = append(toks, t)
		}
	}
	if len(toks) == 0 {
		return nil
	}

	owner := p.prevOwner
	ttl := p.ttl
	ttlSet := p.ttlSet
	class := ClassIN
	pos := 0
	// A blank owner defaults to the previous record's (RFC 1035 5.1); a token
	// that parses as TTL, class or type is not an owner (BIND-compatible).
	if !isTTL(toks[0].text) && !isClass(toks[0].text) && !isType(toks[0].text) {
		var err error
		if owner, err = p.domain(toks[0].text); err != nil {
			return fmt.Errorf("zone: line %d: %w", toks[0].line, err)
		}
		pos = 1
	}
	for pos < len(toks) {
		t := toks[pos]
		if v, err := strconv.ParseUint(t.text, 10, 32); err == nil {
			ttl = uint32(v)
			ttlSet = true
			pos++
			continue
		}
		if c, ok := classToken(t.text); ok {
			class = c
			pos++
			continue
		}
		break
	}
	if !ttlSet {
		ttl = defaultTTL
	}
	if pos >= len(toks) {
		return fmt.Errorf("zone: line %d: missing record type", toks[len(toks)-1].line)
	}
	typ, ok := typeToken(toks[pos].text)
	if !ok {
		return fmt.Errorf("zone: line %d: unknown record type %q", toks[pos].line, toks[pos].text)
	}
	pos++
	rr, err := p.rdata(typ, class, ttl, owner, toks[pos:])
	if err != nil {
		return err
	}
	p.prevOwner = owner
	return p.zone.Add(rr)
}

func (p *parser) rdata(typ Type, class Class, ttl uint32, owner string, toks []token) (*RR, error) {
	line := toks[0].line
	need := func(n int) error {
		if len(toks) != n {
			return fmt.Errorf("zone: line %d: %s record needs %d field(s), got %d", line, typ, n, len(toks))
		}
		return nil
	}
	nameField := func(s string) (string, error) {
		name, err := p.domain(s)
		if err != nil {
			return "", fmt.Errorf("zone: line %d: %w", line, err)
		}
		return name, nil
	}
	switch typ {
	case TypeA:
		if err := need(1); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(toks[0].text)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("zone: line %d: invalid IPv4 address %q", line, toks[0].text)
		}
		return &RR{Name: owner, Type: typ, Class: class, TTL: ttl, Data: AData{Addr: addr}}, nil
	case TypeAAAA:
		if err := need(1); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(toks[0].text)
		if err != nil || !addr.Is6() {
			return nil, fmt.Errorf("zone: line %d: invalid IPv6 address %q", line, toks[0].text)
		}
		return &RR{Name: owner, Type: typ, Class: class, TTL: ttl, Data: AAAAData{Addr: addr}}, nil
	case TypeNS, TypeCNAME, TypePTR:
		if err := need(1); err != nil {
			return nil, err
		}
		name, err := nameField(toks[0].text)
		if err != nil {
			return nil, err
		}
		return &RR{Name: owner, Type: typ, Class: class, TTL: ttl, Data: DomainData{Name: name}}, nil
	case TypeMX:
		if err := need(2); err != nil {
			return nil, err
		}
		pref, err := strconv.ParseUint(toks[0].text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("zone: line %d: invalid MX preference %q", line, toks[0].text)
		}
		name, err := nameField(toks[1].text)
		if err != nil {
			return nil, err
		}
		return &RR{Name: owner, Type: typ, Class: class, TTL: ttl, Data: MXData{Preference: uint16(pref), Name: name}}, nil
	case TypeTXT:
		if len(toks) < 1 {
			return nil, fmt.Errorf("zone: line %d: TXT record needs at least one string", line)
		}
		strs := make([]string, len(toks))
		for i, t := range toks {
			strs[i] = t.text
		}
		return &RR{Name: owner, Type: typ, Class: class, TTL: ttl, Data: TXTData{Strings: strs}}, nil
	case TypeSOA:
		if err := need(7); err != nil {
			return nil, err
		}
		mname, err := nameField(toks[0].text)
		if err != nil {
			return nil, err
		}
		rname, err := nameField(toks[1].text)
		if err != nil {
			return nil, err
		}
		nums := make([]uint32, 5)
		for i, t := range toks[2:] {
			v, err := strconv.ParseUint(t.text, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("zone: line %d: invalid SOA field %q", t.line, t.text)
			}
			nums[i] = uint32(v)
		}
		return &RR{
			Name: owner, Type: typ, Class: class, TTL: ttl,
			Data: SOAData{
				MName: mname, RName: rname,
				Serial: nums[0], Refresh: nums[1], Retry: nums[2],
				Expire: nums[3], Minimum: nums[4],
			},
		}, nil
	case TypeSRV:
		if err := need(4); err != nil {
			return nil, err
		}
		prio, err := strconv.ParseUint(toks[0].text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("zone: line %d: invalid SRV priority %q", line, toks[0].text)
		}
		weight, err := strconv.ParseUint(toks[1].text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("zone: line %d: invalid SRV weight %q", line, toks[1].text)
		}
		port, err := strconv.ParseUint(toks[2].text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("zone: line %d: invalid SRV port %q", line, toks[2].text)
		}
		target, err := nameField(toks[3].text)
		if err != nil {
			return nil, err
		}
		return &RR{
			Name: owner, Type: typ, Class: class, TTL: ttl,
			Data: SRVData{Priority: uint16(prio), Weight: uint16(weight), Port: uint16(port), Name: target},
		}, nil
	default:
		return nil, fmt.Errorf("zone: line %d: unsupported record type %s", line, typ)
	}
}

func isTTL(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func isClass(s string) bool {
	_, ok := classToken(s)
	return ok
}

func isType(s string) bool {
	_, ok := typeToken(s)
	return ok
}

func classToken(s string) (Class, bool) {
	switch strings.ToUpper(s) {
	case "IN":
		return ClassIN, true
	case "CH":
		return ClassCH, true
	case "HS":
		return ClassHS, true
	case "ANY":
		return ClassANY, true
	}
	return 0, false
}

func typeToken(s string) (Type, bool) {
	switch strings.ToUpper(s) {
	case "A":
		return TypeA, true
	case "NS":
		return TypeNS, true
	case "CNAME":
		return TypeCNAME, true
	case "SOA":
		return TypeSOA, true
	case "PTR":
		return TypePTR, true
	case "MX":
		return TypeMX, true
	case "TXT":
		return TypeTXT, true
	case "AAAA":
		return TypeAAAA, true
	case "SRV":
		return TypeSRV, true
	}
	return 0, false
}
