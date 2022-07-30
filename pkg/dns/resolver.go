package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/shiyunjin/elegant-dns/utils/cache"
	"github.com/shiyunjin/elegant-dns/utils/picker"
	"go.uber.org/atomic"
	"math/rand"
	"net/netip"
	"time"

	"github.com/shiyunjin/elegant-dns/pkg/geodata/router"
	"github.com/shiyunjin/elegant-dns/pkg/resolver"
	"github.com/shiyunjin/elegant-dns/pkg/trie"

	D "github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type dnsClient interface {
	Exchange(m *D.Msg) (msg *D.Msg, err error)
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	hosts                 *trie.DomainTrie[netip.Addr]
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []fallbackDomainFilter
	fallbackIPFilters     []fallbackIPFilter
	fallbackIPv6          bool
	group                 singleflight.Group
	lruCache              *cache.LruCache[string, *D.Msg]
	policy                *trie.DomainTrie[*Policy]
	proxyServer           []dnsClient
}

func (r *Resolver) ResolveAllIPPrimaryIPv4(host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.resolveIP(host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ips, err = r.resolveIP(host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

func (r *Resolver) ResolveAllIP(host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.resolveIP(host, D.TypeAAAA)
		if err != nil {
			return
		}

		ch <- ip
	}()

	ips, err = r.resolveIP(host, D.TypeA)

	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ips = append(ips, ipv6s...)
	case <-time.After(1 * time.Millisecond):
		// wait ipv6 result
	}

	return ips, nil
}

func (r *Resolver) ResolveAllIPv4(host string) (ips []netip.Addr, err error) {
	return r.resolveIP(host, D.TypeA)
}

func (r *Resolver) ResolveAllIPv6(host string) (ips []netip.Addr, err error) {
	return r.resolveIP(host, D.TypeAAAA)
}

// ResolveIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) ResolveIP(host string) (ip netip.Addr, err error) {
	if ips, err := r.ResolveAllIPPrimaryIPv4(host); err == nil {
		return ips[rand.Intn(len(ips))], nil
	} else {
		return netip.Addr{}, err
	}
}

// ResolveIPv4 request with TypeA
func (r *Resolver) ResolveIPv4(host string) (ip netip.Addr, err error) {
	if ips, err := r.ResolveAllIPv4(host); err == nil {
		return ips[rand.Intn(len(ips))], nil
	} else {
		return netip.Addr{}, err
	}
}

// ResolveIPv6 request with TypeAAAA
func (r *Resolver) ResolveIPv6(host string) (ip netip.Addr, err error) {
	if ips, err := r.ResolveAllIPv6(host); err == nil {
		return ips[rand.Intn(len(ips))], nil
	} else {
		return netip.Addr{}, err
	}
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.Match(ip) {
			return true
		}
	}
	return false
}

// Exchange a batch of dns request, and it use cache
func (r *Resolver) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return r.ExchangeContext(context.Background(), m)
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}

	q := m.Question[0]
	cacheM, expireTime, hit := r.lruCache.GetWithExpire(q.String())
	if hit {
		now := time.Now()
		msg = cacheM.Copy()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			go r.exchangeWithoutCache(ctx, m)
		} else {
			setMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m)
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := m.Question[0]

	ret, err, shared := r.group.Do(q.String(), func() (result any, err error) {
		defer func() {
			if err != nil {
				return
			}

			msg := result.(*D.Msg)

			putMsgToCache(r.lruCache, q.String(), msg)
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			return r.batchExchange(ctx, matched, m)
		}
		return r.batchExchange(ctx, r.main, m)
	})

	if err == nil {
		msg = ret.(*D.Msg)
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	fast, ctx := picker.WithTimeout[*D.Msg](ctx, resolver.DefaultDNSTimeout)
	for _, client := range clients {
		r := client
		fast.Go(func() (*D.Msg, error) {
			m, err := r.ExchangeContext(ctx, m)
			if err != nil {
				return nil, err
			} else if m.Rcode == D.RcodeServerFailure || m.Rcode == D.RcodeRefused {
				return nil, errors.New("server failure")
			}
			return m, nil
		})
	}

	elm := fast.Wait()
	if elm == nil {
		err := errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = fmt.Errorf("%w, first error: %s", err, fErr.Error())
		}
		return nil, err
	}

	msg = elm
	return
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := msgToDomain(m)
	if domain == "" {
		return nil
	}

	record := r.policy.Search(domain)
	if record == nil {
		return nil
	}

	p := record.Data
	return p.GetData()
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.Match(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil || len(r.fallback) == 0 { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			if !r.shouldIPFallback(ips[0]) {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return
			}
		} else {
			msg, err = res.Msg, res.Error
			return
		}
	}

	res = <-r.asyncExchange(ctx, r.fallback, m)
	msg, err = res.Msg, res.Error

	if !r.fallbackIPv6 && msg != nil && len(msg.Question) != 0 && msg.Question[0].Qtype == D.TypeAAAA {
		return handleMsgWithEmptyAnswer(msg), errors.New("fallback ipv6 disable")
	}

	return
}

func (r *Resolver) resolveIP(host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return []netip.Addr{}, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.Exchange(query)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = msgToIP(msg)
	ipLength := len(ips)
	if ipLength == 0 {
		return []netip.Addr{}, resolver.ErrIPNotFound
	}

	return
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, err := r.batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// HasProxyServer has proxy server dns client
func (r *Resolver) HasProxyServer() bool {
	return len(r.main) > 0
}

type NameServer struct {
	Net       string
	Addr      string
	Interface *atomic.String
}

type FallbackFilter struct {
	GeoIP     bool
	GeoIPCode string
	IPCIDR    []*netip.Prefix
	Domain    []string
	GeoSite   []*router.DomainMatcher
	IPv6      bool
}

type Config struct {
	Main, Fallback []NameServer
	Default        []NameServer
	ProxyServer    []NameServer
	IPv6           bool
	FallbackFilter FallbackFilter
	Hosts          *trie.DomainTrie[netip.Addr]
	Policy         map[string]NameServer
}

func NewResolver(config Config) *Resolver {
	defaultResolver := &Resolver{
		main:     transform(config.Default, nil),
		lruCache: cache.NewLRUCache[string, *D.Msg](cache.WithSize[string, *D.Msg](4096), cache.WithStale[string, *D.Msg](true)),
	}

	r := &Resolver{
		ipv6:         config.IPv6,
		main:         transform(config.Main, defaultResolver),
		lruCache:     cache.NewLRUCache[string, *D.Msg](cache.WithSize[string, *D.Msg](4096), cache.WithStale[string, *D.Msg](true)),
		hosts:        config.Hosts,
		fallbackIPv6: config.FallbackFilter.IPv6,
	}

	if len(config.Fallback) != 0 {
		r.fallback = transform(config.Fallback, defaultResolver)
	}

	if len(config.ProxyServer) != 0 {
		r.proxyServer = transform(config.ProxyServer, defaultResolver)
	}

	if len(config.Policy) != 0 {
		r.policy = trie.New[*Policy]()
		for domain, nameserver := range config.Policy {
			_ = r.policy.Insert(domain, NewPolicy(transform([]NameServer{nameserver}, defaultResolver)))
		}
	}

	fallbackIPFilters := []fallbackIPFilter{}
	if config.FallbackFilter.GeoIP {
		fallbackIPFilters = append(fallbackIPFilters, &geoipFilter{
			code: config.FallbackFilter.GeoIPCode,
		})
	}
	for _, ipnet := range config.FallbackFilter.IPCIDR {
		fallbackIPFilters = append(fallbackIPFilters, &ipnetFilter{ipnet: ipnet})
	}
	r.fallbackIPFilters = fallbackIPFilters

	fallbackDomainFilters := []fallbackDomainFilter{}
	if len(config.FallbackFilter.Domain) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, NewDomainFilter(config.FallbackFilter.Domain))
	}

	if len(config.FallbackFilter.GeoSite) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, &geoSiteFilter{
			matchers: config.FallbackFilter.GeoSite,
		})
	}
	r.fallbackDomainFilters = fallbackDomainFilters

	return r
}
