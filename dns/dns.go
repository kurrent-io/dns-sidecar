package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	// We want our sidecar as tiny as possible, so the split horizon dns solution is as cheap as
	// possible, so work hard to avoid dependencies.

	// Even importing our own k8s apis triples our binary size (!)
	// "github.com/kurrent-io/kurrentdb-operator/pkg/api/v1"
)

/* Example config:

   {
	 "listen": "127.0.0.1:53",
	 "resolver": "10.96.0.10:53"
	 "rules": [
	   # operator generates regex rules to reduce pod reconfigurations/restarts during resize
	   {"host": "db-([0-9]+).my.domain", "result": "db-\\1.ns.svc.cluster.local", "regex": true},
	   {"host": "db-replica-([0-9]+).my.domain", "result": "db-replica-\\1.ns.svc.cluster.local", "regex": true},
	   # additional user-provided rules, through some vpc peering opaque to us
	   {"host": "far-pod0.my.domain", "result": "10.1.2.3"},
	   {"host": "far-pod1.my.domain", "result": "10.1.2.4"}
	 ]
   }

*/

type DNSRule struct {
	Host   string `json:"host"`
	Result string `json:"result"`
	Regex  bool   `json:"regex,omitempty"`
}

type Config struct {
	Listen   string    `json:"listen"`
	Resolver string    `json:"resolver"`
	Rules    []DNSRule `json:"rules"`
}

type BitWriter struct {
	bits uint8
	n    int
	byts []uint8
}

func (b *BitWriter) PutBits(bits... uint8) {
	for _, bit := range bits {
		b.bits = (b.bits << 1) | bit
		b.n++
		if b.n == 8 {
			b.byts = append(b.byts, b.bits)
			b.bits = 0
			b.n = 0
		}
	}
}

func (b *BitWriter) Put8(u uint8) {
	b.byts = append(b.byts, u)
}

func (b *BitWriter) Put16(u uint16) {
	b.Put8(uint8((u >> 8)))
	b.Put8(uint8((u >> 0)))
}

func (b *BitWriter) Put32(u uint32) {
	b.Put8(uint8((u >> 24)))
	b.Put8(uint8((u >> 16)))
	b.Put8(uint8((u >> 8)))
	b.Put8(uint8((u >> 0)))
}

func (b *BitWriter) PutLabel(s string) {
	byts := []byte(s)
	b.Put8(byte(len(byts)))
	for _, byt := range(byts) {
		b.Put8(byt)
	}
}

// returns an offset you can pass to PutNamePtr
func (b *BitWriter) PutDomain(dom string) int {
	start := len(b.byts)
	for _, label := range strings.Split(dom, ".") {
		b.PutLabel(label)
	}
	b.Put8(0)
	return start
}

func (b *BitWriter) PutNamePtr(off int) {
	b.Put16(0xc000 | uint16(off))
}

var EndOfPacket = errors.New("end of packet")

type BitReader struct {
	byts []uint8
	used int
	err  error
	bits uint8
	n    int
}

func (b *BitReader) GetN(n int) uint8 {
	if n < 1 || n > 8 {
		panic("invalid GetN()")
	}
	if b.err != nil {
		return 0
	}
	if b.n == 0 {
		if b.used >= len(b.byts) {
			b.err = EndOfPacket
			return 0
		}
		b.n = 8
		b.bits = b.byts[b.used]
		b.used++
	}
	if n > b.n {
		panic("misaligned access")
	}
	// take the top n bits
	out := b.bits >> (8-n)
	// leave the remaining bits
	b.bits = b.bits << n
	b.n -= n
	return out
}

func (b *BitReader) Get8() uint8 {
	if b.n != 0 {
		panic("misaligned access")
	}
	if b.err != nil {
		return 0
	}
	if b.used + 1 > len(b.byts) {
		b.err = EndOfPacket
		return 0
	}
	out := b.byts[b.used]
	b.used++
	return out
}

func (b *BitReader) Get16() uint16 {
	if b.n != 0 {
		panic("misaligned access")
	}
	if b.err != nil {
		return 0
	}
	if b.used + 2 > len(b.byts) {
		b.err = EndOfPacket
		return 0
	}
	var out uint16 = uint16(b.byts[b.used]) << 8
	out = out | (uint16(b.byts[b.used + 1]))
	b.used += 2
	return out
}

func (b *BitReader) Get32() uint32 {
	if b.n != 0 {
		panic("misaligned access")
	}
	if b.err != nil {
		return 0
	}
	if b.used + 4 > len(b.byts) {
		b.err = EndOfPacket
		return 0
	}
	var out uint32 = uint32(b.byts[b.used]) << 24
	out = out | (uint32(b.byts[b.used + 1]) << 16)
	out = out | (uint32(b.byts[b.used + 2]) << 8)
	out = out | (uint32(b.byts[b.used + 3]))
	b.used += 4
	return out
}

func (b *BitReader) GetString(n int) string {
	if b.n != 0 {
		panic("misaligned access")
	}
	if b.err != nil {
		return ""
	}
	if b.used + n > len(b.byts) {
		b.err = EndOfPacket
		return ""
	}
	out := string(b.byts[b.used:b.used+n])
	b.used += n
	return out
}

func (b *BitReader) GetLabel() (*BitReader, string) {
	n := int(b.Get8())
	if b.err != nil {
		return b, ""
	}
	// check for name pointer
	if n & 0xc0 == 0xc0 {
		off := int(b.Get8())
		if b.err != nil {
			return b, ""
		}
		off = ((n ^ 0xc0) << 8) | off
		// create a new BitReader
		b2 := &BitReader{byts: b.byts, used: off}
		return b2.GetLabel()
	}
	s := b.GetString(n)
	return b, s
}

func (b *BitReader) GetDomain() string {
	var labels []string
	for {
		var label string
		b, label = b.GetLabel()
		if label == "" {
			return strings.Join(labels, ".")
		}
		labels = append(labels, label)
	}
}

func dnsResponse(
	rcode []byte, id uint16, rd byte, domain string, qtype uint16, ips []net.IP,
) []byte {
	// keep only ipv4s for qtype=A queries and ipv6s for qtype=AAAA queries
	wantv4 := qtype == 1  // A
	var usefulIps []net.IP
	for _, ip := range ips {
		isv4 := ip.To4() != nil
		if isv4 == wantv4 {
			usefulIps = append(usefulIps, ip)
		}
	}
	w := BitWriter{}
	// header
	w.Put16(id) // id
	w.PutBits(1)  // qr, 1=response
	w.PutBits(0,0,0,0)  // opcode
	w.PutBits(0)  // aa
	w.PutBits(0)  // tc
	w.PutBits(rd)  // rd
	w.PutBits(1)  // ra
	w.PutBits(0, 0, 0)  // z
	w.PutBits(rcode...)  // rcode
	w.Put16(1)  // qdcount
	w.Put16(uint16(len(usefulIps)))  // ancount
	w.Put16(0)  // nscount
	w.Put16(0)  // arcount
	// question
	nameOff := w.PutDomain(domain)
	w.Put16(qtype) // qtype
	w.Put16(1) // qclass, always IN=1
	// answer
	for _, ip := range usefulIps {
		w.PutNamePtr(nameOff)
		if ip.To4() != nil {
			ipv4 := ip.To4()
			w.Put16(1)  // rtype A=1
			w.Put16(1)  // rclass IN=1
			w.Put32(60)  // TTL
			w.Put16(4)  // rdlen for A record
			for _, byt := range ipv4 {
				w.Put8(byt)
			}
		} else {
			ipv6 := ip.To16()
			w.Put16(28)  // rtype AAAA=28
			w.Put16(1)  // rclass IN=1
			w.Put32(60)  // TTL
			w.Put16(16)  // rdlen for A record
			for _, byt := range ipv6 {
				w.Put8(byt)
			}
		}
	}
	return w.byts
}

var (
	DnsOk = []byte{0,0,0,0}
	DnsSrvfail = []byte{0,0,1,0}  // 2
)

func DNS(
	ctx context.Context,
	listenAddr string,
	resolverAddr string,
	lookupFn func(string) (string, bool),
) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	// always close
	defer sock.Close()
	// when context is canceled, shut down
	go func() {
		<-ctx.Done()
		sock.Close()
	}()

	// start a resolver pointing at a real dns resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * time.Duration(5),
			}
			return d.DialContext(ctx, network, resolverAddr)
		},
	}

	dnsRespondOne := func(buf []byte, src net.Addr) (error) {
		// parse header from bytes
		b := BitReader{byts: buf}
		// header
		id := b.Get16()
		qr := b.GetN(1)
		opcode := b.GetN(4)
		_ = b.GetN(1) // aa
		_ = b.GetN(1) // tc
		rd := b.GetN(1)
		_ = b.GetN(1) // ra
		_ = b.GetN(3) // z
		_ = b.GetN(4) // rcode
		qdcount := b.Get16() // qdcount
		_ = b.Get16() // ancount
		_ = b.Get16() // nscount
		_ = b.Get16() // arcount
		if b.err != nil {
			return b.err
		}

		// ignore strange queries
		//  - non-queries
		//  - non-standard queries
		//  - reject multiple questions
		if qr != 0 || opcode != 0 || qdcount != 1 {
			return nil
		}

		domain := b.GetDomain()
		qtype := b.Get16()
		qclass := b.Get16()
		if b.err != nil {
			return b.err
		}

		// ignore non-IN-class queries
		if qclass != 1 {
			return nil
		}

		// capture a bunch of small variables
		respond := func(rcode []byte, ips []net.IP) error {
			byts := dnsResponse(rcode, id, rd, domain, qtype, ips)
			_, err = sock.WriteTo(byts, src)
			return err
		}

		// we only have answers for qtype=A or qtype=AAAA queries
		if qtype != 1 && qtype != 28 {
			return respond(DnsSrvfail, nil)
		}

		// decide if this name belongs to us or not
		hostOrIp, ok := lookupFn(domain)
		if !ok {
			// not a query for us; send DnsSrvfail so client can check the next resolver immediately
			return respond(DnsSrvfail, nil)
		}

		// check if we got an ip address or a cname
		ip := net.ParseIP(hostOrIp)
		if ip != nil {
			// we got an IP; no need to query the base resolver
			return respond(DnsOk, []net.IP{ip})
		}

		// we'll have to do an async lookup and respond afterwards
		lookup := func() error {
			results, err := resolver.LookupHost(ctx, hostOrIp)
			if err != nil {
				// lookup failed, but don't crash just because we failed a dns lookup
				fmt.Fprintf(os.Stderr, "LookupHost(%v): %v\n", hostOrIp, err)
				return respond(DnsSrvfail, nil)
			}
			// parse IPs from strings (they should all be valid)
			var ips []net.IP
			for _, result := range results {
				ip := net.ParseIP(result)
				if ip == nil {
					fmt.Fprintf(os.Stderr,
						"ParseIP(%v) after LookupHost(%v): %v\n", result, hostOrIp, err,
					)
					continue
				}
				ips = append(ips, ip)
			}
			// even if ips is empty, this is our domain and rcode=OK is correct)
			return respond(DnsOk, ips)
		}
		go func() {
			err := lookup()
			if err != nil {
				// lookup() only returns fatal errors, but we're in the background, so Exit()
				fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
				os.Exit(1)
			}
		}()
		return nil
	}

	for {
		var buf [2048]byte
		n, src, err := sock.ReadFrom(buf[:])
		if err != nil {
			return err
		}
		err = dnsRespondOne(buf[:n], src)
		if err != nil && !errors.Is(err, EndOfPacket) {
			return err
		}
	}
}

func MakeLookupFunc(rules []DNSRule) (func(string) (string, bool), error) {
	// capture each dns rule into a closure
	ruleFns := []func(string)(string, bool){}
	for _, rule := range rules {
		if rule.Regex {
			// regex rule
			re, err := regexp.Compile(rule.Host)
			if err != nil {
				return nil, fmt.Errorf("compiling regex rule (host=%q): %w", rule.Host, err)
			}
			ruleFns = append(ruleFns, func(host string) (string, bool) {
				// require a complete match
				if re.FindString(host) != host {
					return "", false
				}
				return re.ReplaceAllString(host, rule.Result), true
			})
		} else {
			// literal (non-regex) rule
			ruleFns = append(ruleFns, func(host string) (string, bool) {
				if host != rule.Host {
					return "", false
				}
				return rule.Result, true
			})
		}
	}
	// capture all rules into a single lookup function
	return func(host string) (string, bool) {
		for _, ruleFn := range ruleFns {
			if out, ok := ruleFn(host); ok {
				return out, true
			}
		}
		return "", false
	}, nil
}
