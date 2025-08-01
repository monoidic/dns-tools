package main

import (
	"bytes"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/monoidic/dns"
)

type spfMechanism uint8

const (
	spfMechanismAll spfMechanism = iota + 1
	spfMechanismInclude
	spfMechanismA
	spfMechanismMx
	spfMechanismPtr
	spfMechanismIp4
	spfMechanismIp6
	spfMechanismExists
)

var spfMechanismMap = map[string]spfMechanism{
	"all":     spfMechanismAll,
	"include": spfMechanismInclude,
	"a":       spfMechanismA,
	"mx":      spfMechanismMx,
	"ptr":     spfMechanismPtr,
	"ip4":     spfMechanismIp4,
	"ip6":     spfMechanismIp6,
	"exists":  spfMechanismExists,
}

type spfQualifier uint8

const (
	spfQualifierPass spfQualifier = iota + 1
	spfQualifierFail
	spfQualifierSoftfail
	spfQualifierNeutral
)

var spfQualifierMap = map[byte]spfQualifier{
	'+': spfQualifierPass,
	'-': spfQualifierFail,
	'~': spfQualifierSoftfail,
	'?': spfQualifierNeutral,
}

type spfModifierType uint8

const (
	spfModifierTypeRedirect spfModifierType = iota + 1
	spfModifierTypeExplanation
	spfModifierTypeUnknown
)

const (
	// ( "%{" macro-letter transformers *delimiter "}" ) / "%%" / "%_" / "%-"
	// c/r/t excluded, explanation-string only
	macroExpand = `%{[slodiphv][0-9]*r?[-.+,/_=]*}|%[%_-]`
	// ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
	topLabel = `(?i:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])`
	// ( "." toplabel [ "." ] ) / macro-expand
	domainEnd = `(?:\.` + topLabel + `\.?|` + macroExpand + `)`
	// *( macro-expand / macro-literal )
	macroString = `(?:` + macroExpand + `|[!-$&-~])*`

	ipv4Cidr = `/(?:3[0-2]|[12]?[0-9])`
	ipv6Cidr = `/(?:12[0-8]|(?:1[01]|[1-9])?[0-9])`
	dualCidr = `(?P<v4cidr>` + ipv4Cidr + `)?(?:/(?P<v6cidr>` + ipv6Cidr + `))?`
)

var (
	patternName        = compileExactMatch(`(?i)[a-z][a-z0-9_.-]*`)
	patternMacroString = compileExactMatch(macroString)
	patternIPv4CIDR    = compileExactMatch(ipv4Cidr)
	patternIPv6CIDR    = compileExactMatch(ipv6Cidr)
	patternDualCidr    = compileExactMatch(dualCidr)
	patternRecord      = compileExactMatch(`v=spf1(?P<terms>(?: +[^ ]+)+)? *`)
	patternDirective   = compileExactMatch(`(?P<qualifier>[+?~-]?)(?P<mechanism>(?i)i(?:nclude|p[46])|a(?:ll)?|exists|ptr|mx)(?P<remainder>.*)`)
	patternDomainSpec  = compileExactMatch(macroString + domainEnd)
)

var (
	patternDualCidrMap  = getPatternNameMap(patternDualCidr)
	patternRecordMap    = getPatternNameMap(patternRecord)
	patternDirectiveMap = getPatternNameMap(patternDirective)
)

type spfData struct {
	terms      []any
	names      []string
	spfNames   []string
	anyUnknown bool
}

type spfDirective struct {
	name        string // cannot be empty, if it exists; check existence with domain == ""
	address     netip.Addr
	isMacroName bool
	qualifier   spfQualifier
	mechanism   spfMechanism
	v4cidr      uint8
	v6cidr      uint8
	hasV4Cidr   bool
	hasV6Cidr   bool
}

type spfModifier struct {
	key         string // only for spfModifierTypeUnknown
	spec        string
	modType     spfModifierType
	isMacroName bool
}

func parseSPF(txt []byte) (ret spfData, err error) {
	matches := patternRecord.FindSubmatch(txt)
	if matches == nil {
		return ret, Error{s: "invalid SPF record, unable to find version v=spf1 at beginning"}
	}

	if err = ret.parseTerms(matches[patternRecordMap["terms"]]); err != nil {
		return spfData{}, err
	}

	if err = ret.extractData(); err != nil {
		return spfData{}, err
	}

	return ret, err
}

func (data *spfData) extractData() error {
extractDataL:
	for _, term := range data.terms {
		var name string
		var isMacro, isSPFName bool
		switch termT := term.(type) {
		case spfDirective:
			name = termT.name
			isMacro = termT.isMacroName
			isSPFName = termT.mechanism == spfMechanismInclude
		case spfModifier:
			switch termT.modType {
			case spfModifierTypeRedirect, spfModifierTypeExplanation:
				name = termT.spec
				isMacro = termT.isMacroName
				isSPFName = termT.modType == spfModifierTypeRedirect
			case spfModifierTypeUnknown:
				data.anyUnknown = true
				continue extractDataL // don't try anything with unknown modifiers
			}
		default:
			panic("unknown modifier")
		}
		if len(name) == 0 {
			continue
		}
		if isMacro {
			var ok bool
			if name, ok = macroToConstantDomain(name); !ok {
				continue
			}
		}
		name = strings.ToLower(name)
		if isSPFName {
			data.spfNames = append(data.spfNames, name)
		} else {
			data.names = append(data.names, name)
		}
	}
	return nil
}

func macroToConstantDomain(macro string) (constant string, ok bool) {
	index := strings.LastIndexByte(macro, '%')
	constSectionStart := strings.IndexByte(macro[index:], '.') + index
	if constSectionStart == len(macro)-1 { // matched final "." in fqdn
		return "", false
	}
	return macro[constSectionStart+1:], true
}

func (spf *spfData) parseTerms(txt []byte) (err error) {
	for _, field := range bytes.Fields(txt) {
		var parsed bool
		if parsed, err = spf.tryParseDirective(field); err != nil {
			return err
		}

		if !parsed {
			if err = spf.parseModifier(field); err != nil {
				return err
			}
		}
	}

	return nil
}

func (spf *spfData) tryParseDirective(txt []byte) (parsed bool, err error) {
	directive := bytes.SplitN(txt, []byte{' '}, 2)[0]
	directiveParts := patternDirective.FindSubmatch(directive)

	if directiveParts == nil {
		return false, nil
	}

	qualifier := directiveParts[patternDirectiveMap["qualifier"]]
	mechanism := bytes.ToLower(directiveParts[patternDirectiveMap["mechanism"]])
	remainder := directiveParts[patternDirectiveMap["remainder"]]

	if err = spf.parseDirective(qualifier, mechanism, remainder); err != nil {
		return false, err
	}

	return true, nil
}

func (spf *spfData) parseDirective(qualifierB, mechanismB, remainderB []byte) (err error) {
	directive := spfDirective{qualifier: spfQualifierPass, mechanism: spfMechanismMap[string(mechanismB)]}
	if len(qualifierB) != 0 {
		directive.qualifier = spfQualifierMap[qualifierB[0]]
	}

	colonI := bytes.IndexByte(remainderB, ':')
	slashI := bytes.IndexByte(remainderB, '/')
	var domainNet, cidr []byte

	if slashI != -1 {
		cidr = remainderB[slashI:]
	}
	if colonI != -1 {
		end := len(remainderB)
		if slashI != -1 {
			end = slashI
		}
		domainNet = remainderB[colonI+1 : end]
	}

	switch directive.mechanism { // handle domainNet
	case spfMechanismAll:
		if len(remainderB) > 0 {
			return Error{s: "unexpected data after `all` directive"}
		}
	case spfMechanismInclude, spfMechanismA, spfMechanismMx, spfMechanismPtr, spfMechanismExists:
		if len(domainNet) == 0 {
			switch directive.mechanism {
			case spfMechanismInclude, spfMechanismExists:
				return Error{s: "missing required domain in `include`/`exists`"}
			}
		} else {
			if !patternDomainSpec.Match(domainNet) {
				return Error{s: "invalid domain-spec"}
			}
			directive.isMacroName = bytes.ContainsRune(domainNet, '%')
			directive.name = dns.Fqdn(string(domainNet))
		}
	case spfMechanismIp4, spfMechanismIp6:
		if directive.address, err = netip.ParseAddr(string(domainNet)); err != nil {
			return err
		}
		var matchingType bool
		switch directive.mechanism {
		case spfMechanismIp4:
			matchingType = directive.address.Is4()
		case spfMechanismIp6:
			matchingType = directive.address.Is6()
		}
		if !matchingType {
			return Error{s: "mismatching IP type in `ip4`/`ip6` directive"}
		}
	}

	if len(cidr) > 0 {
		switch directive.mechanism { // handle cidr
		case spfMechanismAll, spfMechanismInclude, spfMechanismPtr, spfMechanismExists:
			return Error{s: "unexpected cidr in `all`/`include`/`ptr`/`exists` directive"}
		case spfMechanismA, spfMechanismMx:
			matches := patternDualCidr.FindSubmatch(cidr)
			if matches == nil {
				return Error{s: "invalid dual-cidr in `a`/`mx` directive"}
			}

			if v4cidr := matches[patternDualCidrMap["v4cidr"]]; len(v4cidr) > 0 {
				if directive.v4cidr, err = parseCidrNum(v4cidr); err != nil {
					return err
				}
				directive.hasV4Cidr = true
			}
			if v6cidr := matches[patternDualCidrMap["v4cidr"]]; len(v6cidr) > 0 {
				if directive.v6cidr, err = parseCidrNum(v6cidr); err != nil {
					return err
				}
				directive.hasV6Cidr = true
			}
		case spfMechanismIp4:
			if !patternIPv4CIDR.Match(cidr) {
				return Error{s: "invalid ip4 cidr"}
			}
			if directive.v4cidr, err = parseCidrNum(cidr); err != nil {
				return err
			}
			directive.hasV4Cidr = true
		case spfMechanismIp6:
			if !patternIPv6CIDR.Match(cidr) {
				return Error{s: "invalid ip6 cidr"}
			}
			if directive.v6cidr, err = parseCidrNum(cidr); err != nil {
				return err
			}
			directive.hasV6Cidr = true
		}
	}

	spf.terms = append(spf.terms, directive)
	return nil
}

func (spf *spfData) parseModifier(txt []byte) error {
	modifier := spfModifier{}
	modifierParts := bytes.SplitN(txt, []byte{'='}, 2)
	if len(modifierParts) != 2 {
		return Error{s: "unexpected sequence in SPF record, not directive or modifier"}
	}

	key := modifierParts[0]
	spec := modifierParts[1]

	switch string(bytes.ToLower(key)) {
	case "redirect":
		modifier.modType = spfModifierTypeRedirect
	case "exp":
		modifier.modType = spfModifierTypeExplanation
	default:
		modifier.modType = spfModifierTypeUnknown
	}

	switch modifier.modType {
	case spfModifierTypeRedirect, spfModifierTypeExplanation:
		if !patternDomainSpec.Match(spec) {
			return Error{s: "invalid domain spec"}
		}
	case spfModifierTypeUnknown:
		if !patternName.Match(key) {
			return Error{s: "invalid unknown-modifier name"}
		}
		if !patternMacroString.Match(spec) {
			return Error{s: "invalid macro string in unknown-modifier"}
		}
		modifier.key = string(key)
	default:
		panic("unknown modifier")
	}
	modifier.spec = dns.Fqdn(string(spec))
	modifier.isMacroName = bytes.ContainsRune(spec, '%')
	spf.terms = append(spf.terms, modifier)
	return nil
}

func getPatternNameMap(pattern *regexp.Regexp) map[string]int {
	names := pattern.SubexpNames()
	ret := make(map[string]int, len(names)-1) // assumes all matches are named
	for i, key := range names {
		if key == "" {
			continue
		}
		if _, ok := ret[key]; ok {
			panic("duplicate key: " + key)
		}
		ret[key] = i
	}

	return ret
}

func parseCidrNum(b []byte) (uint8, error) {
	unum, err := strconv.ParseUint(string(b[1:]), 10, 8)
	return uint8(unum), err
}

func compileExactMatch(pattern string) *regexp.Regexp {
	return regexp.MustCompile(`^` + pattern + `$`)
}
