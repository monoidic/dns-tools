package main

import (
	"encoding/json"
	"os"
)

type conf struct {
	Ns                   []string
	AxfrWhitelistedZones []string
	AxfrWhitelistedIPs   []string
	SplitSize            int
	Retries              int
}

var (
	usedNs                 []string
	usedNsLen              int
	AxfrWhitelistedZoneSet = make(Set[string])
	AxfrWhitelistedIPSet   = make(Set[string])
	splitSize              int
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
	splitSize = globalConf.SplitSize
	if globalConf.SplitSize == 0 {
		splitSize = 2
	}

	for _, zone := range globalConf.AxfrWhitelistedZones {
		AxfrWhitelistedZoneSet.Add(zone)
	}

	for _, ip := range globalConf.AxfrWhitelistedIPs {
		AxfrWhitelistedIPSet.Add(ip)
	}
}
