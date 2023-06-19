package main

import (
	"fmt"
	"regexp"
	"strconv"
)

type dmarcFoMask uint8

const (
	dmarcFoValue0 dmarcFoMask = 1 << iota
	dmarcFoValue1
	dmarcFoValueD
	dmarcFoValueS
)

var dmarcFoMaskMap = map[string]dmarcFoMask{
	"0": dmarcFoValue0,
	"1": dmarcFoValue1,
	"d": dmarcFoValueD,
	"s": dmarcFoValueS,
}

type dmarcAlignment uint8

const (
	dmarcAlignmentR dmarcAlignment = iota + 1
	dmarcAlignmentS
)

var dmarcAlignmentMap = map[string]dmarcAlignment{
	"r": dmarcAlignmentR,
	"s": dmarcAlignmentS,
}

type dmarcPolicy uint8

const (
	dmarcPolicyNone dmarcPolicy = iota + 1
	dmarcPolicyQuarantine
	dmarcPolicyReject
)

var dmarcPolicyMap = map[string]dmarcPolicy{
	"none":       dmarcPolicyNone,
	"quarantine": dmarcPolicyQuarantine,
	"reject":     dmarcPolicyReject,
}

type dmarcTag uint8

const (
	dmarcTagP dmarcTag = iota + 1
	dmarcTagSP
	dmarcTagRUA
	dmarcTagRUF
	dmarcTagADKIM
	dmarcTagASPF
	dmarcTagInterval
	dmarcTagFO
	dmarcTagRF
	dmarcTagPct
	dmarcTagVer
)

type dmarcTagMask uint16

const (
	dmarcTagMaskP        dmarcTagMask = 1 << (dmarcTagP - 1)
	dmarcTagMaskSP                    = 1 << (dmarcTagSP - 1)
	dmarcTagMaskRUA                   = 1 << (dmarcTagRUA - 1)
	dmarcTagMaskRUF                   = 1 << (dmarcTagRUF - 1)
	dmarcTagMaskADKIM                 = 1 << (dmarcTagADKIM - 1)
	dmarcTagMaskASPF                  = 1 << (dmarcTagASPF - 1)
	dmarcTagMaskInterval              = 1 << (dmarcTagInterval - 1)
	dmarcTagMaskFO                    = 1 << (dmarcTagFO - 1)
	dmarcTagMaskRF                    = 1 << (dmarcTagRF - 1)
	dmarcTagMaskPct                   = 1 << (dmarcTagPct - 1)
	dmarcTagMaskVer                   = 1 << (dmarcTagVer - 1)
)

var dmarcTagToMask = map[dmarcTag]dmarcTagMask{
	dmarcTagP:        dmarcTagMaskP,
	dmarcTagSP:       dmarcTagMaskSP,
	dmarcTagRUA:      dmarcTagMaskRUA,
	dmarcTagRUF:      dmarcTagMaskRUF,
	dmarcTagADKIM:    dmarcTagMaskADKIM,
	dmarcTagASPF:     dmarcTagMaskASPF,
	dmarcTagInterval: dmarcTagMaskInterval,
	dmarcTagFO:       dmarcTagMaskFO,
	dmarcTagRF:       dmarcTagMaskRF,
	dmarcTagPct:      dmarcTagMaskPct,
	dmarcTagVer:      dmarcTagMaskVer,
}

const (
	// host        = IP-literal / IPv4address / reg-name
	// reg-name    = *( unreserved / pct-encoded / sub-delims )
	// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
	// uriRegname      = `(?i:[-a-z0-9~._!$&'()*+,;=]|%[0-9a-f]{2})*`
	//	uriIpv4Octet    = `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
	//	uriIpv4OctetDot = uriIpv4Octet + `\.`
	//	uriIPv4         = uriIpv4OctetDot + uriIpv4OctetDot + uriIpv4OctetDot + uriIpv4Octet

	// TODO validate host part
	uriHost = `(?i:[-0-9a-f.:[\]]+)`

	uriPchar        = `(?i:[-a-z0-9~._!$&'()*+,;=:@]|%[0-9a-f]{2})`
	uriPathRootless = uriSegmentNZ + uriPathAbempty
	uriPathAbsolute = `/(?:` + uriPathRootless + `)?`
	uriQuery        = `(?:` + uriPchar + `|[?/])*`
	uriFragment     = uriQuery
	uriSegment      = uriPchar + `*`
	uriSegmentNZ    = uriPchar + `+`
	uriPathAbempty  = `(?:/` + uriSegment + `)*`
	uriScheme       = `(?i:[a-z][-a-z0-9+.]*)`
	uriUserinfo     = `(?i:[-a-z0-9~._!$&'()*+,;=:]|%[0-9a-f]{2})*`
	uriAuthority    = `(?:` + uriUserinfo + `@)?` + uriHost + `(?::[0-9]+)?`
	uriHier         = `(?:` +
		`//` + uriAuthority + uriPathAbempty +
		`|` + uriPathAbsolute +
		`|` + uriPathRootless +
		`)?` // ? handles path-empty

	uriUri   = uriScheme + `:` + uriHier + `(?:\?` + uriQuery + `)?(?:#` + uriFragment + `)?`
	dmarcUri = uriUri + `(?:![0-9]+[kmgt]?)?`
	// TODO validate above

	ebnfWsp     = `[ \t]*`
	smtpKeyword = `(?i:[a-z0-9-]*[a-z0-9])`

	dmarcSep        = ebnfWsp + `;` + ebnfWsp
	dmarcFoSep      = ebnfWsp + `:` + ebnfWsp
	dmarcRfSep      = ebnfWsp + `:`
	dmarcUriSep     = ebnfWsp + `,` + ebnfWsp
	dmarcPatternSep = ebnfWsp + `=` + ebnfWsp
)

var (
	// permissive: `(?P<value>.*?)` + ebnfWsp, strict: `(?P<value>.*)`
	patternDmarcTag  = compileExactMatch(`(?P<key>[a-z]+)` + dmarcPatternSep + `(?P<value>.*?)` + ebnfWsp)
	patternDmarcVer  = compileExactMatch(`DMARC1`)
	patternUri       = compileExactMatch(dmarcUri + `(?:` + dmarcUriSep + dmarcUri + `)*`)
	patternPolicy    = compileExactMatch(`none|quarantine|reject`)
	patternAlignment = compileExactMatch(`r|s`)
	patternInterval  = compileExactMatch(`[0-9]+`)
	patternFo        = compileExactMatch(`[01ds](?:` + dmarcFoSep + `[01ds])*`)
	patternRf        = compileExactMatch(smtpKeyword + `(?:` + dmarcRfSep + smtpKeyword + `)*`)
	patternPercent   = compileExactMatch(`[0-9]{1,3}`)
	patternDmarcSep  = regexp.MustCompile(dmarcSep)
	patternFoSep     = regexp.MustCompile(dmarcFoSep)
)

var (
	patternDmarcTagMap = getPatternNameMap(patternDmarcTag)
)

var dmarcTagToPattern = map[dmarcTag]*regexp.Regexp{
	dmarcTagP:        patternPolicy,
	dmarcTagSP:       patternPolicy,
	dmarcTagRUA:      patternUri,
	dmarcTagRUF:      patternUri,
	dmarcTagADKIM:    patternAlignment,
	dmarcTagASPF:     patternAlignment,
	dmarcTagInterval: patternInterval,
	dmarcTagFO:       patternFo,
	dmarcTagRF:       patternRf,
	dmarcTagPct:      patternPercent,

	dmarcTagVer: patternDmarcVer,
}

var dmarcTagMap = map[string]dmarcTag{
	"p":     dmarcTagP,
	"sp":    dmarcTagSP,
	"rua":   dmarcTagRUA,
	"ruf":   dmarcTagRUF,
	"adkim": dmarcTagADKIM,
	"aspf":  dmarcTagASPF,
	"ri":    dmarcTagInterval,
	"fo":    dmarcTagFO,
	"rf":    dmarcTagRF,
	"pct":   dmarcTagPct,

	"v": dmarcTagVer,
}

type dmarcRecord struct {
	p         dmarcPolicy
	sp        dmarcPolicy
	rua       string
	ruf       string
	rf        string
	interval  uint32
	entryMask dmarcTagMask
	adkim     dmarcAlignment
	aspf      dmarcAlignment
	fo        dmarcFoMask
	pct       uint8
}

func parseDmarc(s string) (dmarcRecord, error) {
	ret := dmarcRecord{ // defaults
		adkim:    dmarcAlignmentR,
		aspf:     dmarcAlignmentR,
		fo:       dmarcFoValue0,
		pct:      100,
		rf:       "afrf",
		interval: 86400,
		// v, p are mandatory; rua/ruf have no defaults; sp defaults to p
	}
	parts := patternDmarcSep.Split(s, -1)

	if len(parts) < 2 {
		return ret, Error{s: "too few tags in record"}
	}

	// handle empty final tag
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}

	keyI := patternDmarcTagMap["key"]
	valueI := patternDmarcTagMap["value"]

	for i, part := range parts {
		partMatches := patternDmarcTag.FindStringSubmatch(part)
		if partMatches == nil {
			return ret, Error{s: "invalid key-value part"}
		}
		key := partMatches[keyI]
		value := partMatches[valueI]

		keyTag, ok := dmarcTagMap[key]
		if !ok {
			return ret, Error{s: fmt.Sprintf("invalid tag: %q", key)}
		}

		if !dmarcTagToPattern[keyTag].MatchString(value) {
			return ret, Error{s: fmt.Sprintf("invalid value for key %q: %q", key, value)}
		}

		mask := dmarcTagToMask[keyTag]
		if (ret.entryMask & mask) != 0 {
			return ret, Error{s: fmt.Sprintf("duplicate tag: %q", key)}
		}
		ret.entryMask |= mask
		switch keyTag {
		case dmarcTagVer:
			if i != 0 {
				return ret, Error{s: "first tag is not v"}
			}
		case dmarcTagP:
			// required by RFC, but e.g this treats it as a suggestion? https://www.dmarcanalyzer.com/dmarc/dmarc-record-check/
			if i != 1 {
				return ret, Error{s: "second tag is not p"}
			}

			ret.p = dmarcPolicyMap[value]
		case dmarcTagSP:
			ret.sp = dmarcPolicyMap[value]
		// TODO extra verification/extract domain for rua/ruf?
		case dmarcTagRUA:
			ret.rua = value
		case dmarcTagRUF:
			ret.ruf = value
		case dmarcTagADKIM:
			ret.adkim = dmarcAlignmentMap[value]
		case dmarcTagASPF:
			ret.aspf = dmarcAlignmentMap[value]
		case dmarcTagInterval:
			if num, err := strconv.ParseUint(value, 10, 32); err == nil {
				ret.interval = uint32(num)
			} else {
				return ret, err
			}
		case dmarcTagFO:
			ret.fo = 0
			foParts := patternFoSep.Split(value, -1)
			for _, foPart := range foParts {
				foMask := dmarcFoMaskMap[foPart]
				if (ret.fo & foMask) != 0 {
					return ret, Error{s: fmt.Sprintf("invalid fo tag, duplicate %s entry", foPart)}
				}
				ret.fo |= foMask
			}
		case dmarcTagRF: // TODO something here?
			ret.rf = value
		case dmarcTagPct:
			if num, err := strconv.ParseUint(value, 10, 8); err == nil {
				if num > 100 {
					return ret, Error{s: fmt.Sprintf("invalid percent, %d > 100", num)}
				}
				ret.pct = uint8(num)
			} else {
				return ret, err
			}
		}
	}

	if desiredMask := dmarcTagMaskP | dmarcTagMaskVer; ret.entryMask&desiredMask != desiredMask {
		return ret, Error{s: "missing v or p tag"}
	}
	if ret.entryMask&dmarcTagMaskSP != dmarcTagMaskSP {
		ret.sp = ret.p
	}

	return ret, nil
}
