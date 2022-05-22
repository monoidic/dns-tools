package main

import (
	"encoding/json"
	"os"
)

type conf struct {
	Ns                   []string
	AxfrWhitelistedZones []string
	AxfrWhitelistedIPs   []string
}

var usedNs []string
var usedNsLen int
var AxfrWhitelistedZoneSet = make(map[string]bool)
var AxfrWhitelistedIPSet = make(map[string]bool)

var globalConf conf

func readConfig() {
	b, err := os.ReadFile("conf.json")
	check(err)

	check(json.Unmarshal(b, &globalConf))
	usedNs = globalConf.Ns
	usedNsLen = len(usedNs)

	for _, zone := range globalConf.AxfrWhitelistedZones {
		AxfrWhitelistedZoneSet[zone] = true
	}

	for _, ip := range globalConf.AxfrWhitelistedIPs {
		AxfrWhitelistedIPSet[ip] = true
	}
}
