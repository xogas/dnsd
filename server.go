package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxUDPSize is the largest UDP response sent and advertised over EDNS(0)
// (RFC 6891 6.2.5, DNS Flag Day 2020).
const MaxUDPSize = 1232

const (
	maxUDPPacket = 65535 // largest legal DNS datagram
	tcpIdle      = 30 * time.Second
	tcpWrite     = 10 * time.Second
)

// Config configures a Server.
type Config struct {
	Addr      string // listen address, used for both UDP and TCP
	Zones     []*Zone
	Upstream  string        // host:port of a recursive resolver; empty disables recursion
	Timeout   time.Duration // timeout for upstream queries
	CacheSize int           // maximum number of cached responses
	Logger    *slog.Logger
}

func (c *Config) defaults() {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.CacheSize <= 0 {
		c.CacheSize = 4096
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Server is a DNS daemon serving one address over UDP and TCP.
type Server struct {
	cfg     Config
	log     *slog.Logger
	udp     net.PacketConn
	tcp     net.Listener
	wg      sync.WaitGroup
	cache   *cache
	queries atomic.Int64 // total queries handled; observable by tests
}

// New returns a Server with the given configuration.
func New(cfg Config) *Server {
	cfg.defaults()
	return &Server{
		cfg:   cfg,
		log:   cfg.Logger,
		cache: newCache(cfg.CacheSize),
	}
}

// Listen binds the UDP and TCP listeners on the configured address.
func (s *Server) Listen() error {
	udp, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("binding udp %s: %w", s.cfg.Addr, err)
	}
	tcp, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("binding tcp %s: %w", s.cfg.Addr, err)
	}
	s.udp, s.tcp = udp, tcp
	return nil
}

// UDPAddr returns the bound UDP address (valid after Listen).
func (s *Server) UDPAddr() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

// TCPAddr returns the bound TCP address (valid after Listen).
func (s *Server) TCPAddr() net.Addr {
	if s.tcp == nil {
		return nil
	}
	return s.tcp.Addr()
}

// ListenAndServe binds the listeners and serves until ctx is cancelled,
// then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	s.log.Info("dnsd listening", "udp", s.UDPAddr(), "tcp", s.TCPAddr())
	return s.Serve(ctx)
}

// Serve runs until ctx is cancelled or a listener fails, then waits for
// in-flight handlers to finish (bounded by a safety timeout).
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.udp.Close()
		_ = s.tcp.Close()
	}()
	errCh := make(chan error, 2)
	go func() { errCh <- s.serveUDP(ctx) }()
	go func() { errCh <- s.serveTCP(ctx) }()
	var first error
	for range 2 {
		if err := <-errCh; err != nil && first == nil {
			first = err
		}
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return first
}

// serveUDP reads datagrams and answers each in a bounded goroutine.
func (s *Server) serveUDP(ctx context.Context) error {
	sem := make(chan struct{}, 1024)
	buf := make([]byte, maxUDPPacket)
	for {
		n, remote, err := s.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("udp read: %w", err)
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			s.log.Warn("dropping query: overloaded", "remote", remote.String())
			continue
		}
		s.wg.Add(1)
		go func() {
			defer func() { s.wg.Done(); <-sem }()
			if resp := s.answer(remote.String(), pkt, -1); resp != nil {
				if _, err := s.udp.WriteTo(resp, remote); err != nil {
					s.log.Debug("udp write failed", "remote", remote.String(), "error", err)
				}
			}
		}()
	}
}

// serveTCP accepts connections and serves each one sequentially.
func (s *Server) serveTCP(ctx context.Context) error {
	sem := make(chan struct{}, 256)
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tcp accept: %w", err)
		}
		select {
		case sem <- struct{}{}:
		default:
			s.log.Warn("dropping connection: overloaded", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer func() { s.wg.Done(); <-sem }()
			s.serveConn(conn)
		}()
	}
}

// serveConn answers queries on one TCP connection: length-prefixed messages
// (RFC 1035 4.2.2), many queries per connection (RFC 7766).
func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close() //nolint: errcheck
	remote := conn.RemoteAddr().String()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdle))
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		n := int(lb[0])<<8 | int(lb[1])
		if n == 0 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		resp := s.answer(remote, msg, MaxMessageSize)
		if resp == nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(tcpWrite))
		out := make([]byte, 2+len(resp))
		out[0], out[1] = byte(len(resp)>>8), byte(len(resp))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// answer handles one query and returns the packed response. limit < 0 means
// UDP mode (truncate to the EDNS(0) size or 512 bytes); otherwise it caps the
// packed size directly (TCP mode). nil drops the exchange.
func (s *Server) answer(remote string, pkt []byte, limit int) []byte {
	req, err := Unpack(pkt)
	if err != nil {
		s.log.Debug("malformed query", "remote", remote, "error", err)
		return formerrResponse(pkt)
	}
	if req.Header.QR {
		return nil // responses sent to the server are ignored
	}
	s.queries.Add(1)
	start := time.Now()
	resp := s.handleQuery(req)
	packed, err := resp.Pack()
	if err != nil {
		s.log.Warn("packing response", "error", err)
		return formerrResponse(pkt)
	}
	if limit < 0 {
		limit = udpLimit(req)
	}
	if len(packed) > limit {
		packed = truncateMessage(resp, limit)
	}
	name, typ, class := logQuestion(req)
	s.log.Info("query",
		"remote", remote, "name", name, "type", typ, "class", class,
		"rcode", resp.Header.Rcode.String(), "size", len(packed),
		"duration", time.Since(start).Round(time.Microsecond),
	)
	return packed
}

// handleQuery builds the response message for a parsed query.
func (s *Server) handleQuery(req *Message) *Message {
	resp := &Message{
		Header: Header{
			ID:     req.Header.ID,
			QR:     true,
			Opcode: req.Header.Opcode,
			RD:     req.Header.RD,
			CD:     req.Header.CD,
			RA:     s.cfg.Upstream != "",
		},
	}
	if len(req.Question) == 1 {
		resp.Question = req.Question // echo the question, case and all
	}
	reqOpt := FindOPT(req.Additional)
	switch {
	case req.Header.Opcode != OpcodeQuery:
		resp.Header.Rcode = RcodeNotImp
	case len(req.Question) != 1:
		resp.Header.Rcode = RcodeFormErr
	default:
		q := req.Question[0]
		if q.Class != ClassIN && q.Class != ClassANY {
			resp.Header.Rcode = RcodeRefused
			break
		}
		if reqOpt != nil {
			// EDNS(0) version negotiation (RFC 6891 section 6.1.3).
			if opt, ok := reqOpt.Data.(OPTData); ok && opt.Version != 0 {
				resp.Header.Rcode = RcodeBadVers
				break
			}
		}
		qname := CanonicalName(q.Name)
		if z := s.zoneFor(qname); z != nil {
			s.authoritative(resp, z, qname, q.Type, q.Class)
		} else if s.cfg.Upstream != "" && req.Header.RD {
			s.recursive(resp, q)
		} else {
			resp.Header.Rcode = RcodeRefused
		}
	}
	// Answer with an OPT record when the query advertised EDNS(0)
	// (RFC 6891 section 6.1.1).
	if reqOpt != nil {
		resp.Additional = append(resp.Additional, &RR{
			Name: ".", Type: TypeOPT,
			Class: Class(MaxUDPSize),
			Data:  OPTData{UDPSize: MaxUDPSize},
		})
	}
	return resp
}

// authoritative answers from zone z (RFC 1034 4.3.2): matching records, the
// CNAME rule, or a negative response with the SOA (RFC 2308).
func (s *Server) authoritative(resp *Message, z *Zone, qname string, typ Type, class Class) {
	resp.Header.AA = true
	res := z.Lookup(qname, typ, class)
	switch {
	case res.NXDomain:
		resp.Header.Rcode = RcodeNXDomain
		if soa := z.SOA(); soa != nil {
			resp.Authority = []*RR{soa}
		}
	case len(res.Records) == 0:
		// NODATA: the name exists but not with the requested type.
		if soa := z.SOA(); soa != nil {
			resp.Authority = []*RR{soa}
		}
	default:
		resp.Answer = res.Records
		resp.Additional = s.glue(z, res.Records)
	}
}

// glue returns A/AAAA records for the targets named by NS, MX and SRV
// answers (RFC 1035 4.3.2, RFC 2782).
func (s *Server) glue(z *Zone, answers []*RR) []*RR {
	var out []*RR
	seen := make(map[string]bool)
	for _, rr := range answers {
		var target string
		switch d := rr.Data.(type) {
		case MXData:
			target = d.Name
		case SRVData:
			target = d.Name
		case DomainData:
			if rr.Type == TypeNS {
				target = d.Name
			}
		}
		if target == "" {
			continue
		}
		for _, g := range z.Additional(target) {
			key := g.Name + " " + g.Type.String()
			if !seen[key] {
				seen[key] = true
				out = append(out, g)
			}
		}
	}
	return out
}

// recursive answers q from the cache or by querying upstream, caching the
// result (RFC 2308).
func (s *Server) recursive(resp *Message, q Question) {
	resp.Header.RD = true
	key := cacheKey{name: CanonicalName(q.Name), typ: q.Type, class: q.Class}
	now := time.Now()
	if cached := s.cache.get(key, now); cached != nil {
		s.copyForward(resp, cached)
		return
	}
	up := &Message{
		Header:   Header{ID: randomID(), Opcode: OpcodeQuery, RD: true},
		Question: []Question{q},
		Additional: []*RR{{
			Name: ".", Type: TypeOPT,
			Class: Class(MaxUDPSize),
			Data:  OPTData{UDPSize: MaxUDPSize},
		}},
	}
	packed, err := up.Pack()
	if err != nil {
		resp.Header.Rcode = RcodeServFail
		return
	}
	raw, err := s.exchange(packed)
	if err != nil {
		s.log.Debug("upstream query failed", "upstream", s.cfg.Upstream, "error", err)
		resp.Header.Rcode = RcodeServFail
		return
	}
	reply, err := Unpack(raw)
	if err != nil {
		resp.Header.Rcode = RcodeServFail
		return
	}
	if reply.Header.ID != up.Header.ID || !sameQuestion(reply.Question, q) {
		s.log.Warn("upstream response mismatch", "upstream", s.cfg.Upstream)
		resp.Header.Rcode = RcodeServFail
		return
	}
	if ttl := minTTL(reply); ttl > 0 {
		s.cache.put(key, reply, ttl, now)
	}
	s.copyForward(resp, reply)
}

// copyForward copies a recursive reply (or cached copy) into resp.
func (s *Server) copyForward(resp, reply *Message) {
	resp.Header.AA = reply.Header.AA
	resp.Header.TC = reply.Header.TC
	resp.Header.Rcode = reply.Header.Rcode
	resp.Header.AD = reply.Header.AD
	resp.Answer = reply.Answer
	resp.Authority = reply.Authority
	for _, rr := range reply.Additional {
		if rr.Type != TypeOPT {
			resp.Additional = append(resp.Additional, rr)
		}
	}
}

// exchange sends query to the upstream resolver over UDP and returns the
// raw response, with a timeout.
func (s *Server) exchange(query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", s.cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("dialing upstream %s: %w", s.cfg.Upstream, err)
	}
	defer conn.Close() //nolint: errcheck
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPPacket)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// zoneFor returns the zone whose origin is the longest suffix of name; a
// root zone (".") is a catch-all.
func (s *Server) zoneFor(name string) *Zone {
	var best *Zone
	var root *Zone
	for _, z := range s.cfg.Zones {
		o := z.Origin
		switch {
		case o == ".":
			root = z
		case name == o || strings.HasSuffix(name, "."+o):
			if best == nil || len(o) > len(best.Origin) {
				best = z
			}
		}
	}
	if best == nil {
		best = root
	}
	return best
}

// udpLimit is the largest response the client accepts: 512 bytes without
// EDNS(0), else the advertised payload size (RFC 6891 6.2.3).
func udpLimit(req *Message) int {
	limit := 512
	if opt := FindOPT(req.Additional); opt != nil {
		if d, ok := opt.Data.(OPTData); ok {
			if n := int(d.UDPSize); n > limit {
				limit = n
			}
		}
	}
	// Cap larger advertised sizes at 4096 (RFC 6891 6.2.5).
	if limit > 4096 {
		limit = 4096
	}
	return limit
}

// truncateMessage re-packs resp to fit within limit: drops records from the
// additional, authority and answer sections and sets TC (RFC 2181 9), keeping
// the OPT record as long as possible.
func truncateMessage(resp *Message, limit int) []byte {
	w := *resp
	w.Header.TC = true
	last, _ := w.Pack()
	for len(last) > limit {
		switch {
		case len(w.Answer) > 0:
			w.Answer = w.Answer[:len(w.Answer)-1]
		case len(w.Authority) > 0:
			w.Authority = w.Authority[:len(w.Authority)-1]
		case len(w.Additional) > 0:
			n := len(w.Additional)
			if n == 1 {
				return last // only the OPT record left; cannot shrink further
			}
			if w.Additional[n-1].Type == TypeOPT {
				w.Additional = append(w.Additional[:n-2], w.Additional[n-1])
			} else {
				w.Additional = w.Additional[:n-1]
			}
		default:
			return last
		}
		last, _ = w.Pack()
	}
	return last
}

// formerrResponse builds a minimal FORMERR reply, echoing the ID if present.
func formerrResponse(pkt []byte) []byte {
	if len(pkt) < 2 {
		return nil
	}
	m := &Message{
		Header: Header{ID: binary.BigEndian.Uint16(pkt[:2]), QR: true, Rcode: RcodeFormErr},
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

func sameQuestion(questions []Question, q Question) bool {
	return len(questions) == 1 &&
		CanonicalName(questions[0].Name) == CanonicalName(q.Name) &&
		questions[0].Type == q.Type &&
		questions[0].Class == q.Class
}

func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

// logQuestion returns the question fields for logging.
func logQuestion(req *Message) (name, typ, class string) {
	if len(req.Question) == 0 {
		return "-", "-", "-"
	}
	q := req.Question[0]
	return q.Name, q.Type.String(), q.Class.String()
}

// cacheKey identifies a cached response by question.
type cacheKey struct {
	name  string // canonical
	typ   Type
	class Class
}

type cacheEntry struct {
	expires time.Time
	msg     *Message
}

// cache is an in-memory cache of recursive responses, keyed by question,
// expiring after the response TTL (RFC 1035 3.2.3); negatives per RFC 2308.
type cache struct {
	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
	max     int
}

func newCache(max int) *cache {
	return &cache{entries: make(map[cacheKey]*cacheEntry), max: max}
}

// get returns a cached copy with TTLs reduced by the time in cache, or nil.
func (c *cache) get(key cacheKey, now time.Time) *Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return nil
	}
	if !now.Before(e.expires) {
		delete(c.entries, key)
		return nil
	}
	ttl := uint32(e.expires.Sub(now) / time.Second)
	out := *e.msg
	out.Answer = withTTL(e.msg.Answer, ttl)
	out.Authority = withTTL(e.msg.Authority, ttl)
	out.Additional = withTTL(e.msg.Additional, ttl)
	return &out
}

// put stores a response for ttl seconds, evicting when full.
func (c *cache) put(key cacheKey, m *Message, ttl uint32, now time.Time) {
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= c.max {
		var oldestKey cacheKey
		var oldest time.Time
		first := true
		for k, e := range c.entries {
			if first || e.expires.Before(oldest) {
				oldestKey, oldest, first = k, e.expires, false
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = &cacheEntry{
		expires: now.Add(time.Duration(ttl) * time.Second),
		msg:     m,
	}
}

// minTTL is the caching TTL: the smallest answer TTL, or for negative answers
// the SOA TTL capped by its MINIMUM (RFC 2308 5). 0 means don't cache.
func minTTL(m *Message) uint32 {
	var min uint32 = 1<<32 - 1
	found := false
	for _, rr := range m.Answer {
		if rr.Type == TypeOPT {
			continue
		}
		if rr.TTL < min {
			min = rr.TTL
		}
		found = true
	}
	if found {
		return min
	}
	for _, rr := range m.Authority {
		if rr.Type == TypeSOA {
			soa, ok := rr.Data.(SOAData)
			if !ok {
				return 0
			}
			t := rr.TTL
			if soa.Minimum < t {
				t = soa.Minimum
			}
			return t
		}
	}
	return 0
}

// withTTL returns a shallow copy of rrs with TTLs replaced by ttl, aging
// cached responses. OPT records keep their TTL, which carries flags.
func withTTL(rrs []*RR, ttl uint32) []*RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]*RR, len(rrs))
	for i, rr := range rrs {
		c := *rr
		if c.Type != TypeOPT {
			c.TTL = ttl
		}
		out[i] = &c
	}
	return out
}
