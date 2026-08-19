package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Name limits from RFC 1035 2.3.4 and 4.1.4.
const (
	maxNameLength  = 255
	maxLabelLength = 63
)

var (
	errTruncated   = errors.New("dnsmsg: truncated message")
	errBadLabel    = errors.New("dnsmsg: invalid label length")
	errBadPointer  = errors.New("dnsmsg: invalid compression pointer")
	errNameTooLong = errors.New("dnsmsg: name exceeds 255 bytes")
	errTooManyHops = errors.New("dnsmsg: too many compression pointers")
)

// CanonicalName lowercases name and trims trailing dots (RFC 4343) so it can
// be used as a key for zone lookups and the cache. The root is ".".
func CanonicalName(name string) string {
	name = strings.ToLower(strings.TrimRight(name, "."))
	if name == "" {
		return "."
	}
	return name
}

// encoder serializes names, compressing repeated label suffixes (RFC 1035 4.1.4).
type encoder struct {
	buf  bytes.Buffer
	comp map[string]int // name -> offset of its first occurrence
}

// writeName writes name, pointing to the longest suffix already written.
func (e *encoder) writeName(name string) error {
	if name == "" || name == "." {
		e.buf.WriteByte(0)
		return nil
	}
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels); i++ {
		off, ok := e.comp[CanonicalName(strings.Join(labels[i:], "."))]
		if ok && off <= 0x3FFF { // 14-bit pointer field
			for j := 0; j < i; j++ {
				if err := writeLabel(&e.buf, labels[j]); err != nil {
					return err
				}
			}
			e.buf.WriteByte(0xC0 | byte(off>>8))
			e.buf.WriteByte(byte(off))
			return nil
		}
	}
	for i := 0; i < len(labels); i++ {
		key := CanonicalName(strings.Join(labels[i:], "."))
		if _, ok := e.comp[key]; !ok {
			e.comp[key] = e.buf.Len()
		}
		if err := writeLabel(&e.buf, labels[i]); err != nil {
			return err
		}
	}
	e.buf.WriteByte(0)
	return nil
}

func writeLabel(b *bytes.Buffer, label string) error {
	if len(label) == 0 || len(label) > maxLabelLength {
		return fmt.Errorf("dnsmsg: label %q exceeds %d bytes", label, maxLabelLength)
	}
	b.WriteByte(byte(len(label)))
	b.WriteString(label)
	return nil
}

// readName decodes the name at off (original case, root as ".") and returns
// the next offset; compression pointers are followed with loop/bounds checks.
func readName(b []byte, off int) (string, int, error) {
	var labels []string
	pos := off
	end := -1
	hops := 0
	total := 0
	for {
		if pos >= len(b) {
			return "", 0, fmt.Errorf("%w at byte %d", errTruncated, off)
		}
		n := int(b[pos])
		switch {
		case n == 0: // root label terminates the name
			if end < 0 {
				end = pos + 1
			}
			if len(labels) == 0 {
				return ".", end, nil
			}
			return strings.Join(labels, "."), end, nil
		case n&0xC0 == 0xC0: // compression pointer
			if pos+1 >= len(b) {
				return "", 0, fmt.Errorf("%w at byte %d", errTruncated, off)
			}
			target := (n&0x3F)<<8 | int(b[pos+1])
			if target >= pos { // pointers must point strictly backwards
				return "", 0, fmt.Errorf("%w at byte %d", errBadPointer, off)
			}
			if end < 0 {
				end = pos + 2
			}
			hops++
			if hops > 16 {
				return "", 0, fmt.Errorf("%w at byte %d", errTooManyHops, off)
			}
			pos = target
		case n&0xC0 != 0: // reserved label types
			return "", 0, fmt.Errorf("%w at byte %d", errBadLabel, off)
		default:
			if pos+1+n > len(b) {
				return "", 0, fmt.Errorf("%w at byte %d", errTruncated, off)
			}
			total += n + 1
			if total > maxNameLength {
				return "", 0, fmt.Errorf("%w at byte %d", errNameTooLong, off)
			}
			labels = append(labels, string(b[pos+1:pos+1+n]))
			pos += 1 + n
		}
	}
}

const headerSize = 12

// MaxMessageSize is the largest message fitting the TCP length field (RFC 1035 4.2.2).
const MaxMessageSize = 65535

// Type is a resource record type (RFC 1035 section 3.2.2).
type Type uint16

// Record types known to dnsd.
const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41
	TypeANY   Type = 255
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA",
	TypeSRV: "SRV", TypeOPT: "OPT", TypeANY: "ANY",
}

// String returns the mnemonic from RFC 1035 and friends, or the RFC 3597
// "TYPE<n>" form for unknown types.
func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// Class is a resource record class (RFC 1035 section 3.2.4).
type Class uint16

const (
	ClassIN  Class = 1
	ClassCH  Class = 3
	ClassHS  Class = 4
	ClassANY Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	case ClassCH:
		return "CH"
	case ClassHS:
		return "HS"
	case ClassANY:
		return "ANY"
	}
	return fmt.Sprintf("CLASS%d", uint16(c))
}

// Opcode is the operation code field (RFC 1035 section 4.1.1).
type Opcode uint8

const (
	OpcodeQuery  Opcode = 0
	OpcodeIQuery Opcode = 1
	OpcodeStatus Opcode = 2
	OpcodeNotify Opcode = 4
	OpcodeUpdate Opcode = 5
)

func (o Opcode) String() string {
	switch o {
	case OpcodeQuery:
		return "QUERY"
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeUpdate:
		return "UPDATE"
	}
	return fmt.Sprintf("OPCODE%d", uint8(o))
}

// Rcode is a response code. Values above 15 are extended codes carried in
// the OPT record (RFC 6891 section 6.1.3).
type Rcode uint8

const (
	RcodeNoError  Rcode = 0
	RcodeFormErr  Rcode = 1
	RcodeServFail Rcode = 2
	RcodeNXDomain Rcode = 3
	RcodeNotImp   Rcode = 4
	RcodeRefused  Rcode = 5
	RcodeYXDomain Rcode = 6
	RcodeYXRrset  Rcode = 7
	RcodeNXRrset  Rcode = 8
	RcodeNotAuth  Rcode = 9
	RcodeNotZone  Rcode = 10
	RcodeBadVers  Rcode = 16 // extended code, carried in the OPT record
)

func (r Rcode) String() string {
	switch r {
	case RcodeNoError:
		return "NOERROR"
	case RcodeFormErr:
		return "FORMERR"
	case RcodeServFail:
		return "SERVFAIL"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNotImp:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	case RcodeYXDomain:
		return "YXDOMAIN"
	case RcodeYXRrset:
		return "YXRRSET"
	case RcodeNXRrset:
		return "NXRRSET"
	case RcodeNotAuth:
		return "NOTAUTH"
	case RcodeNotZone:
		return "NOTZONE"
	case RcodeBadVers:
		return "BADVERS"
	}
	return fmt.Sprintf("RCODE%d", uint8(r))
}

// Header is the fixed message header (RFC 1035 section 4.1.1).
type Header struct {
	ID     uint16
	QR     bool
	Opcode Opcode
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	Z      bool // reserved, must be zero
	AD     bool // RFC 4035 3.1.6
	CD     bool // RFC 4035 3.1.7
	Rcode  Rcode
}

// Question is a question section entry (RFC 1035 section 4.1.2).
type Question struct {
	Name  string // presentation form, original case; "." for the root
	Type  Type
	Class Class
}

// String returns the "name class type" form used in logs.
func (q Question) String() string {
	return fmt.Sprintf("%s %s %s", q.Name, q.Class, q.Type)
}

// RR is a resource record (RFC 1035 4.1.3); Data is the type-specific RDATA.
type RR struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32
	Data  any
}

// Message is a DNS message: header plus the four sections.
type Message struct {
	Header     Header
	Question   []Question
	Answer     []*RR
	Authority  []*RR
	Additional []*RR
}

// Pack serializes the message; an extended rcode above 15 is carried in the
// OPT record (RFC 6891 6.1.3).
func (m *Message) Pack() ([]byte, error) {
	e := &encoder{comp: make(map[string]int)}
	h := m.Header
	rcode := uint16(h.Rcode)
	// With an extended rcode the upper bits travel in the OPT record
	// (RFC 6891 section 6.1.3); write a copy carrying them.
	var opt *RR
	if o := FindOPT(m.Additional); o != nil && rcode > 0xF {
		d, ok := o.Data.(OPTData)
		if !ok {
			return nil, fmt.Errorf("dnsmsg: OPT record has %T data", o.Data)
		}
		d.ExtRcode = uint8(rcode >> 4)
		opt = &RR{Name: o.Name, Type: TypeOPT, Class: o.Class, TTL: o.TTL, Data: d}
	}

	e.buf.WriteByte(byte(h.ID >> 8))
	e.buf.WriteByte(byte(h.ID))
	var flags [2]byte
	if h.QR {
		flags[0] |= 0x80
	}
	flags[0] |= byte(h.Opcode&0xF) << 3
	if h.AA {
		flags[0] |= 0x04
	}
	if h.TC {
		flags[0] |= 0x02
	}
	if h.RD {
		flags[0] |= 0x01
	}
	if h.RA {
		flags[1] |= 0x80
	}
	if h.Z {
		flags[1] |= 0x40
	}
	if h.AD {
		flags[1] |= 0x20
	}
	if h.CD {
		flags[1] |= 0x10
	}
	flags[1] |= byte(rcode & 0xF)
	e.buf.Write(flags[:])
	var counts [8]byte
	binary.BigEndian.PutUint16(counts[0:2], uint16(len(m.Question)))
	binary.BigEndian.PutUint16(counts[2:4], uint16(len(m.Answer)))
	binary.BigEndian.PutUint16(counts[4:6], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(counts[6:8], uint16(len(m.Additional)))
	e.buf.Write(counts[:])

	for _, q := range m.Question {
		if err := e.writeQuestion(q); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Answer {
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Authority {
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Additional {
		if opt != nil && rr.Type == TypeOPT {
			// The copy carries the extended rcode (if any).
			if err := e.writeRR(opt); err != nil {
				return nil, err
			}
			continue
		}
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	if e.buf.Len() > MaxMessageSize {
		return nil, fmt.Errorf("dnsmsg: message of %d bytes exceeds %d", e.buf.Len(), MaxMessageSize)
	}
	return e.buf.Bytes(), nil
}

func (e *encoder) writeQuestion(q Question) error {
	if err := e.writeName(q.Name); err != nil {
		return err
	}
	var b [4]byte
	binary.BigEndian.PutUint16(b[0:2], uint16(q.Type))
	binary.BigEndian.PutUint16(b[2:4], uint16(q.Class))
	e.buf.Write(b[:])
	return nil
}

func (e *encoder) writeRR(rr *RR) error {
	if rr.Type == TypeOPT {
		return e.writeOPT(rr)
	}
	if err := e.writeName(rr.Name); err != nil {
		return err
	}
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(rr.Type))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(rr.Class))
	binary.BigEndian.PutUint32(hdr[4:8], rr.TTL)
	e.buf.Write(hdr[:]) // RDLENGTH patched in below
	start := e.buf.Len()
	if err := writeRData(e, rr); err != nil {
		return err
	}
	rdlen := e.buf.Len() - start
	if rdlen > 65535 {
		return fmt.Errorf("dnsmsg: rdata of %d bytes too large", rdlen)
	}
	binary.BigEndian.PutUint16(e.buf.Bytes()[start-2:start], uint16(rdlen))
	return nil
}

// writeOPT writes an OPT pseudo-record (RFC 6891 6.1.2): owner ".", class is
// the UDP payload size, TTL carries the extended rcode, version and flags.
func (e *encoder) writeOPT(rr *RR) error {
	d, ok := rr.Data.(OPTData)
	if !ok {
		return fmt.Errorf("dnsmsg: OPT record has %T data", rr.Data)
	}
	if err := e.writeName("."); err != nil {
		return err
	}
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(TypeOPT))
	binary.BigEndian.PutUint16(hdr[2:4], d.UDPSize)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(d.ExtRcode)<<24|uint32(d.Version)<<16|uint32(d.Flags))
	e.buf.Write(hdr[:])
	start := e.buf.Len()
	for _, o := range d.Options {
		var ob [4]byte
		binary.BigEndian.PutUint16(ob[0:2], o.Code)
		binary.BigEndian.PutUint16(ob[2:4], uint16(len(o.Data)))
		e.buf.Write(ob[:])
		e.buf.Write(o.Data)
	}
	binary.BigEndian.PutUint16(e.buf.Bytes()[start-2:start], uint16(e.buf.Len()-start))
	return nil
}

// Unpack parses a wire-format message; trailing bytes beyond the declared
// sections are ignored.
func Unpack(b []byte) (*Message, error) {
	if len(b) < headerSize {
		return nil, fmt.Errorf("dnsmsg: message shorter than %d bytes", headerSize)
	}
	m := &Message{}
	h := &m.Header
	h.ID = binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	h.QR = flags&0x8000 != 0
	h.Opcode = Opcode(flags >> 11 & 0xF)
	h.AA = flags&0x0400 != 0
	h.TC = flags&0x0200 != 0
	h.RD = flags&0x0100 != 0
	h.RA = flags&0x0080 != 0
	h.Z = flags&0x0040 != 0
	h.AD = flags&0x0020 != 0
	h.CD = flags&0x0010 != 0
	h.Rcode = Rcode(flags & 0xF)
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))

	off := headerSize
	for i := 0; i < qd; i++ {
		q, next, err := readQuestion(b, off)
		if err != nil {
			return nil, err
		}
		m.Question = append(m.Question, q)
		off = next
	}
	for i := 0; i < an; i++ {
		rr, next, err := readRR(b, off)
		if err != nil {
			return nil, err
		}
		m.Answer = append(m.Answer, &rr)
		off = next
	}
	for i := 0; i < ns; i++ {
		rr, next, err := readRR(b, off)
		if err != nil {
			return nil, err
		}
		m.Authority = append(m.Authority, &rr)
		off = next
	}
	for i := 0; i < ar; i++ {
		rr, next, err := readRR(b, off)
		if err != nil {
			return nil, err
		}
		m.Additional = append(m.Additional, &rr)
		off = next
	}
	if opt := FindOPT(m.Additional); opt != nil {
		if d, ok := opt.Data.(OPTData); ok {
			h.Rcode |= Rcode(d.ExtRcode) << 4
		}
	}
	return m, nil
}

func readQuestion(b []byte, off int) (Question, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(b) {
		return Question{}, 0, fmt.Errorf("%w at byte %d", errTruncated, next)
	}
	return Question{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(b[next : next+2])),
		Class: Class(binary.BigEndian.Uint16(b[next+2 : next+4])),
	}, next + 4, nil
}

func readRR(b []byte, off int) (RR, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return RR{}, 0, err
	}
	if next+10 > len(b) {
		return RR{}, 0, fmt.Errorf("%w at byte %d", errTruncated, next)
	}
	rr := RR{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(b[next : next+2])),
		Class: Class(binary.BigEndian.Uint16(b[next+2 : next+4])),
		TTL:   binary.BigEndian.Uint32(b[next+4 : next+8]),
	}
	rdlen := int(binary.BigEndian.Uint16(b[next+8 : next+10]))
	rdata := next + 10
	if rdata+rdlen > len(b) {
		return RR{}, 0, fmt.Errorf("%w at byte %d", errTruncated, rdata)
	}
	if rr.Type == TypeOPT {
		opts, err := readOptions(b, rdata, rdata+rdlen)
		if err != nil {
			return RR{}, 0, err
		}
		ttl := binary.BigEndian.Uint32(b[next+4 : next+8])
		rr.Data = OPTData{
			UDPSize:  uint16(rr.Class),
			ExtRcode: uint8(ttl >> 24),
			Version:  uint8(ttl >> 16),
			Flags:    uint16(ttl),
			Options:  opts,
		}
		return rr, rdata + rdlen, nil
	}
	data, err := readRData(b, rdata, rdlen, rr.Type)
	if err != nil {
		return RR{}, 0, err
	}
	rr.Data = data
	return rr, rdata + rdlen, nil
}

// FindOPT returns the OPT record in additional, or nil (RFC 6891 6.1.1).
func FindOPT(additional []*RR) *RR {
	for _, rr := range additional {
		if rr.Type == TypeOPT {
			return rr
		}
	}
	return nil
}

// RDATA types implement the supported record types; unknown types are kept
// as RawData so responses round-trip (RFC 3597).

// AData is an A record's RDATA: a 32-bit IPv4 address (RFC 1035 3.4.1).
type AData struct {
	Addr netip.Addr
}

// AAAAData is an AAAA record's RDATA: a 128-bit IPv6 address (RFC 3596 2.2).
type AAAAData struct {
	Addr netip.Addr
}

// DomainData is the RDATA of a name-valued record: NS, CNAME, PTR
// (RFC 1035 3.3.1, 3.3.4, 3.3.12).
type DomainData struct {
	Name string
}

// MXData is an MX record's RDATA (RFC 1035 3.3.9).
type MXData struct {
	Preference uint16
	Name       string
}

// TXTData is a TXT record's RDATA: one or more character strings (RFC 1035 3.3.14).
type TXTData struct {
	Strings []string
}

// SOAData is an SOA record's RDATA (RFC 1035 3.3.13).
type SOAData struct {
	MName   string // primary name server
	RName   string // responsible mailbox
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32 // negative caching TTL (RFC 2308 5)
}

// SRVData is the RDATA of an SRV record (RFC 2782).
type SRVData struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Name     string // target
}

// OPTData is an OPT pseudo-record's RDATA (RFC 6891 6.1.2); UDPSize, ExtRcode,
// Version and Flags live in the class and TTL fields on the wire.
type OPTData struct {
	UDPSize  uint16
	ExtRcode uint8
	Version  uint8
	Flags    uint16
	Options  []EDNSOption
}

// EDNSOption is an EDNS(0) option (RFC 6891 section 6.1.2).
type EDNSOption struct {
	Code uint16
	Data []byte
}

// RawData preserves the RDATA of a record type dnsd does not model.
type RawData struct {
	Bytes []byte
}

// readRData decodes RDATA for typ; names inside may use compression pointers
// into the whole message (RFC 1035 4.1.4).
func readRData(b []byte, off, rdlen int, typ Type) (any, error) {
	end := off + rdlen
	switch typ {
	case TypeA:
		if rdlen != 4 {
			return nil, fmt.Errorf("dnsmsg: A rdata is %d bytes, want 4", rdlen)
		}
		var a [4]byte
		copy(a[:], b[off:end])
		return AData{Addr: netip.AddrFrom4(a)}, nil
	case TypeAAAA:
		if rdlen != 16 {
			return nil, fmt.Errorf("dnsmsg: AAAA rdata is %d bytes, want 16", rdlen)
		}
		var a [16]byte
		copy(a[:], b[off:end])
		return AAAAData{Addr: netip.AddrFrom16(a)}, nil
	case TypeNS, TypeCNAME, TypePTR:
		name, next, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, fmt.Errorf("dnsmsg: %s rdata length mismatch", typ)
		}
		return DomainData{Name: name}, nil
	case TypeMX:
		if rdlen < 3 {
			return nil, fmt.Errorf("dnsmsg: MX rdata is %d bytes, want at least 3", rdlen)
		}
		name, next, err := readName(b, off+2)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, fmt.Errorf("dnsmsg: MX rdata length mismatch")
		}
		return MXData{Preference: binary.BigEndian.Uint16(b[off : off+2]), Name: name}, nil
	case TypeTXT:
		var strs []string
		pos := off
		for pos < end {
			n := int(b[pos])
			pos++
			if pos+n > end {
				return nil, fmt.Errorf("dnsmsg: TXT string exceeds rdata")
			}
			strs = append(strs, string(b[pos:pos+n]))
			pos += n
		}
		return TXTData{Strings: strs}, nil
	case TypeSOA:
		mname, next, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		rname, next2, err := readName(b, next)
		if err != nil {
			return nil, err
		}
		if next2+20 != end {
			return nil, fmt.Errorf("dnsmsg: SOA rdata length mismatch")
		}
		return SOAData{
			MName:   mname,
			RName:   rname,
			Serial:  binary.BigEndian.Uint32(b[next2 : next2+4]),
			Refresh: binary.BigEndian.Uint32(b[next2+4 : next2+8]),
			Retry:   binary.BigEndian.Uint32(b[next2+8 : next2+12]),
			Expire:  binary.BigEndian.Uint32(b[next2+12 : next2+16]),
			Minimum: binary.BigEndian.Uint32(b[next2+16 : next2+20]),
		}, nil
	case TypeSRV:
		if rdlen < 7 {
			return nil, fmt.Errorf("dnsmsg: SRV rdata is %d bytes, want at least 7", rdlen)
		}
		name, next, err := readName(b, off+6)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, fmt.Errorf("dnsmsg: SRV rdata length mismatch")
		}
		return SRVData{
			Priority: binary.BigEndian.Uint16(b[off : off+2]),
			Weight:   binary.BigEndian.Uint16(b[off+2 : off+4]),
			Port:     binary.BigEndian.Uint16(b[off+4 : off+6]),
			Name:     name,
		}, nil
	default:
		data := make([]byte, rdlen)
		copy(data, b[off:end])
		return RawData{Bytes: data}, nil
	}
}

func readOptions(b []byte, off, end int) ([]EDNSOption, error) {
	var opts []EDNSOption
	for off < end {
		if off+4 > end {
			return nil, fmt.Errorf("dnsmsg: truncated OPT option")
		}
		code := binary.BigEndian.Uint16(b[off : off+2])
		n := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+n > end {
			return nil, fmt.Errorf("dnsmsg: OPT option exceeds rdata")
		}
		data := make([]byte, n)
		copy(data, b[off:off+n])
		opts = append(opts, EDNSOption{Code: code, Data: data})
		off += n
	}
	return opts, nil
}

// writeRData serializes RDATA; names are compressed against names already
// written (RFC 1035 4.1.4), unknown types pass through verbatim.
func writeRData(e *encoder, rr *RR) error {
	switch d := rr.Data.(type) {
	case AData:
		if rr.Type != TypeA {
			return fmt.Errorf("dnsmsg: AData in %s record", rr.Type)
		}
		if !d.Addr.Is4() {
			return fmt.Errorf("dnsmsg: A record with non-IPv4 address %s", d.Addr)
		}
		a := d.Addr.As4()
		e.buf.Write(a[:])
	case AAAAData:
		if rr.Type != TypeAAAA {
			return fmt.Errorf("dnsmsg: AAAAData in %s record", rr.Type)
		}
		if !d.Addr.Is6() {
			return fmt.Errorf("dnsmsg: AAAA record with non-IPv6 address %s", d.Addr)
		}
		a := d.Addr.As16()
		e.buf.Write(a[:])
	case DomainData:
		if rr.Type != TypeNS && rr.Type != TypeCNAME && rr.Type != TypePTR {
			return fmt.Errorf("dnsmsg: DomainData in %s record", rr.Type)
		}
		return e.writeName(d.Name)
	case MXData:
		if rr.Type != TypeMX {
			return fmt.Errorf("dnsmsg: MXData in %s record", rr.Type)
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], d.Preference)
		e.buf.Write(b[:])
		return e.writeName(d.Name)
	case TXTData:
		if rr.Type != TypeTXT {
			return fmt.Errorf("dnsmsg: TXTData in %s record", rr.Type)
		}
		for _, s := range d.Strings {
			if len(s) > 255 {
				return fmt.Errorf("dnsmsg: TXT string of %d bytes exceeds 255", len(s))
			}
			e.buf.WriteByte(byte(len(s)))
			e.buf.WriteString(s)
		}
	case SOAData:
		if rr.Type != TypeSOA {
			return fmt.Errorf("dnsmsg: SOAData in %s record", rr.Type)
		}
		if err := e.writeName(d.MName); err != nil {
			return err
		}
		if err := e.writeName(d.RName); err != nil {
			return err
		}
		var b [20]byte
		binary.BigEndian.PutUint32(b[0:4], d.Serial)
		binary.BigEndian.PutUint32(b[4:8], d.Refresh)
		binary.BigEndian.PutUint32(b[8:12], d.Retry)
		binary.BigEndian.PutUint32(b[12:16], d.Expire)
		binary.BigEndian.PutUint32(b[16:20], d.Minimum)
		e.buf.Write(b[:])
	case SRVData:
		if rr.Type != TypeSRV {
			return fmt.Errorf("dnsmsg: SRVData in %s record", rr.Type)
		}
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:2], d.Priority)
		binary.BigEndian.PutUint16(b[2:4], d.Weight)
		binary.BigEndian.PutUint16(b[4:6], d.Port)
		e.buf.Write(b[:])
		return e.writeName(d.Name)
	case RawData:
		e.buf.Write(d.Bytes)
	default:
		return fmt.Errorf("dnsmsg: unsupported rdata type %T for %s", rr.Data, rr.Type)
	}
	return nil
}
