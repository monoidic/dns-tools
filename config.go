package main

import (
	"encoding/json"
	"math/rand"
	"os"
)

type conf struct {
	Ns                   []string
	AxfrWhitelistedZones []string
	AxfrWhitelistedIPs   []string
}

var (
	usedNs                 []string
	usedNsLen              int
	AxfrWhitelistedZoneSet = make(map[string]bool)
	AxfrWhitelistedIPSet   = make(map[string]bool)
)

var globalConf conf

func readConfig() {
	b := check1(os.ReadFile("conf.json"))

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

func randomNS() string {
	return usedNs[rand.Intn(usedNsLen)]
}
