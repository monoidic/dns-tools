package main

import (
	"strings"

	"github.com/monoidic/dns"
)

func normalizeRR(rr dns.RR) {
	hdr := rr.Header()
	hdr.Name = strings.ToLower(hdr.Name)
	hdr.Ttl = 0

	switch rrT := rr.(type) {
	case *dns.NS:
		rrT.Ns = strings.ToLower(rrT.Ns)
	case *dns.CNAME:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.DNAME:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.MX:
		rrT.Mx = strings.ToLower(rrT.Mx)
	case *dns.PTR:
		rrT.Ptr = strings.ToLower(rrT.Ptr)
	case *dns.SOA:
		rrT.Ns = strings.ToLower(rrT.Ns)
		rrT.Mbox = strings.ToLower(rrT.Mbox)
	case *dns.NSEC:
		rrT.NextDomain = strings.ToLower(rrT.NextDomain)

	case *dns.MB:
		rrT.Mb = strings.ToLower(rrT.Mb)
	case *dns.MG:
		rrT.Mg = strings.ToLower(rrT.Mg)
	case *dns.MINFO:
		rrT.Rmail = strings.ToLower(rrT.Rmail)
		rrT.Email = strings.ToLower(rrT.Email)
	case *dns.MR:
		rrT.Mr = strings.ToLower(rrT.Mr)
	case *dns.MF:
		rrT.Mf = strings.ToLower(rrT.Mf)
	case *dns.MD:
		rrT.Md = strings.ToLower(rrT.Md)
	case *dns.AFSDB:
		rrT.Hostname = strings.ToLower(rrT.Hostname)
	case *dns.RT:
		rrT.Host = strings.ToLower(rrT.Host)
	case *dns.RP:
		rrT.Mbox = strings.ToLower(rrT.Mbox)
		rrT.Txt = strings.ToLower(rrT.Txt)
	case *dns.SRV:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.NAPTR:
		rrT.Replacement = strings.ToLower(rrT.Replacement)
	case *dns.PX:
		rrT.Map822 = strings.ToLower(rrT.Map822)
		rrT.Mapx400 = strings.ToLower(rrT.Mapx400)
	case *dns.RRSIG:
		rrT.SignerName = strings.ToLower(rrT.SignerName)
	case *dns.KX:
		rrT.Exchanger = strings.ToLower(rrT.Exchanger)
	case *dns.TALINK:
		rrT.PreviousName = strings.ToLower(rrT.PreviousName)
		rrT.NextName = strings.ToLower(rrT.NextName)
	case *dns.IPSECKEY:
		rrT.GatewayHost = strings.ToLower(rrT.GatewayHost)
	case *dns.AMTRELAY:
		rrT.GatewayHost = strings.ToLower(rrT.GatewayHost)
	case *dns.NSAPPTR:
		rrT.Ptr = strings.ToLower(rrT.Ptr)
	case *dns.HIP:
		for i, v := range rrT.RendezvousServers {
			rrT.RendezvousServers[i] = strings.ToLower(v)
		}
	case *dns.LP:
		rrT.Fqdn = strings.ToLower(rrT.Fqdn)
	}
}
