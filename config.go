package main

import (
	"encoding/json"
	"os"
)

type conf struct {
	Ns                   []string
	AxfrWhitelistedZones []string
	AxfrWhitelistedIPs   []string
	Retries              int
}

var (
	usedNs                 []string
	usedNsLen              int
	AxfrWhitelistedZoneSet = make(Set[string])
	AxfrWhitelistedIPSet   = make(Set[string])
)

// read config and populate global variables
func readConfig() {
	var globalConf conf
	b := check1(os.ReadFile("conf.json"))

	check(json.Unmarshal(b, &globalConf))
	usedNs = globalConf.Ns
	retries = globalConf.Retries
	if retries == 0 {
		retries = 10
	}
	usedNsLen = len(usedNs)

	for _, zone := range globalConf.AxfrWhitelistedZones {
		AxfrWhitelistedZoneSet.Add(zone)
	}

	for _, ip := range globalConf.AxfrWhitelistedIPs {
		AxfrWhitelistedIPSet.Add(ip)
	}
}
