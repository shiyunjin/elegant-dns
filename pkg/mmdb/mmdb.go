package mmdb

import (
	"github.com/oschwald/geoip2-golang"
	"github.com/shiyunjin/elegant-dns/utils/log"
	"sync"

	C "github.com/shiyunjin/elegant-dns/model"
)

var (
	mmdb *geoip2.Reader
	once sync.Once
)

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})
}

func Verify() bool {
	instance, err := geoip2.Open(C.Path.MMDB())
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func Instance() *geoip2.Reader {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})

	return mmdb
}