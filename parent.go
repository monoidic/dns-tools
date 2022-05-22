package main

import (
	"github.com/miekg/dns"
)

// modified from miekg/dns Split() to return strings and the root zone (".")
func nameParents(name string) []string {
	if name == "." {
		return []string{}
	}

	var idx []int
	off := 0

	for end := false; end == false; off, end = dns.NextLabel(name, off) {
		idx = append(idx, off)
	}

	idx = append(idx, off-1)

	ret := make([]string, 0, len(idx))
	for _, i := range idx[1:] {
		ret = append(ret, name[i:])
	}

	return ret
}
