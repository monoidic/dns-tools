package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
)

type conf struct {
	Ns                   []string
	AxfrWhitelistedZones []string
	AxfrWhitelistedIPs   []string
}

var (
	usedNs                 []string
	usedNsLen              int
	AxfrWhitelistedZoneSet = make(Set[string])
	AxfrWhitelistedIPSet   = make(Set[string])
)

type Set[T comparable] map[T]struct{}

func (s Set[T]) Contains(key T) bool {
	_, ret := s[key]
	return ret
}

func (s Set[T]) Set(key T) {
	s[key] = struct{}{}
}

func (s Set[T]) Delete(key T) {
	delete(s, key)
}

func (s Set[T]) String() string {
	var b strings.Builder
	check1(b.WriteString(reflect.TypeOf(s).Name())) // e.g "Set[string]"
	check(b.WriteByte('{'))

	first := true
	for e := range s {
		if !first {
			check1(b.WriteString(", "))
		} else {
			first = false
		}
		check1(b.WriteString(fmt.Sprintf("\"%#v\"", e)))
	}

	check(b.WriteByte('}'))

	return b.String()
}

var globalConf conf

// read config and populate global variables
func readConfig() {
	b := check1(os.ReadFile("conf.json"))

	check(json.Unmarshal(b, &globalConf))
	usedNs = globalConf.Ns
	usedNsLen = len(usedNs)

	for _, zone := range globalConf.AxfrWhitelistedZones {
		AxfrWhitelistedZoneSet.Set(zone)
	}

	for _, ip := range globalConf.AxfrWhitelistedIPs {
		AxfrWhitelistedIPSet.Set(ip)
	}
}

// select random nameserver from config
func randomNS() string {
	return usedNs[rand.Intn(usedNsLen)]
}
