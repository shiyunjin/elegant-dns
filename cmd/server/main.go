package main

import (
	"fmt"
	"github.com/shiyunjin/elegant-dns/config"
	C "github.com/shiyunjin/elegant-dns/model"
	"github.com/shiyunjin/elegant-dns/pkg/dns"
	"github.com/shiyunjin/elegant-dns/pkg/resolver"
	"github.com/shiyunjin/elegant-dns/pkg/trie"
	"github.com/shiyunjin/elegant-dns/utils/log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

var (
	homeDir string
)

func main() {

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	buf, err := readConfig(C.Path.Config())
	if err != nil {
		log.Errorln("config file error: %v", err)
		return
	}

	cfg, err := config.Parse(buf)
	if err != nil {
		log.Errorln("config parse error: %v", err)
		return
	}

	updateHosts(cfg.Hosts)
	updateDNS(cfg.DNS)

	log.SetLevel(cfg.General.LogLevel)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func updateHosts(tree *trie.DomainTrie[netip.Addr]) {
	resolver.DefaultHosts = tree
}

func updateDNS(c *config.DNS) {
	cfg := dns.Config{
		Main:     c.NameServer,
		Fallback: c.Fallback,
		IPv6:     c.IPv6,
		Hosts:    c.Hosts,
		FallbackFilter: dns.FallbackFilter{
			GeoIP:     c.FallbackFilter.GeoIP,
			GeoIPCode: c.FallbackFilter.GeoIPCode,
			IPCIDR:    c.FallbackFilter.IPCIDR,
			Domain:    c.FallbackFilter.Domain,
			IPv6:      c.FallbackFilter.IPv6,
		},
		Default: c.DefaultNameserver,
		Policy:  c.NameServerPolicy,
	}

	r := dns.NewResolver(cfg)

	resolver.DefaultResolver = r

	dns.ReCreateServer(c.Listen, r)
}
