package main

import (
	"bytes"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/monoidic/rangeset"
)

type Nsec3Hash struct {
	H [20]byte
}

func (nh Nsec3Hash) String() string {
	return string(base32.HexEncoding.AppendEncode(nil, nh.H[:]))
}

func labelToNsec3Hash(label string) Nsec3Hash {
	var ret Nsec3Hash
	label = strings.ToUpper(label)
	check1(base32.HexEncoding.Decode(ret.H[:], []byte(label)))
	return ret
}

func nsec3RRToHashes(rrT *dns.NSEC3) (Nsec3Hash, Nsec3Hash) {
	start := labelToNsec3Hash(dns.SplitDomainName(rrT.Hdr.Name)[0])
	end := labelToNsec3Hash(rrT.NextDomain)

	return start, end
}

func labelDiff(start, end Nsec3Hash) *big.Int {
	total := &big.Int{}
	switch bytes.Compare(start.H[:], end.H[:]) {
	case 0: // covers whole zone
		return nsec3Total()
	case -1: // start < end
		total = total.Sub(end.toNum(), start.toNum())
	case 1: // start > end, wraparound
		// add up start to ffff... + 0000... to end (=> ffff... - start  + end)
		total = total.Sub(nsec3HashEnd.toNum(), start.toNum())
		total = total.Add(total, end.toNum())
	}

	return total
}

func labelDiffSmall(start, end Nsec3Hash) bool {
	return minDiff.Cmp(labelDiff(start, end)) != -1
}

func (nh *Nsec3Hash) toNum() *big.Int {
	ret := big.NewInt(0)
	part := big.NewInt(0)

	for i := range 2 {
		part = part.SetUint64(binary.BigEndian.Uint64(nh.H[i*8 : i*8+8]))
		ret = ret.Lsh(ret, 64)
		ret = ret.Or(ret, part)
	}

	part = part.SetUint64(uint64(binary.BigEndian.Uint32(nh.H[16:])))
	ret = ret.Lsh(ret, 32)
	ret = ret.Or(ret, part)

	return ret
}

// zero-initialized
var nsec3HashStart = Nsec3Hash{}

// all ones
var nsec3HashEnd = Nsec3Hash{H: [20]byte{
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
}}

type nsec3WalkZone struct {
	zone        string
	id          int64
	knownRanges rangeset.RangeSet[Nsec3Hash]
	rrTypes     map[Nsec3Hash][]string
	salt        []byte
	iterations  int
}

func (wz *nsec3WalkZone) contains(hash Nsec3Hash) bool {
	return wz.knownRanges.Contains(hash)
}

func (wz nsec3WalkZone) String() string {
	var sb strings.Builder

	var nonFirst bool

	for _, rn := range wz.knownRanges.Ranges {
		if nonFirst {
			sb.WriteRune(' ')
		} else {
			nonFirst = true
		}

		sb.WriteString(fmt.Sprintf("%s-%s", string(base32.HexEncoding.AppendEncode(nil, rn.Start.H[:])), string(base32.HexEncoding.AppendEncode(nil, rn.End.H[:]))))
	}

	return sb.String()
}

func nsec3Total() *big.Int {
	all := big.NewInt(1)
	all = all.Lsh(all, 160)
	return all
}

func (wz *nsec3WalkZone) sizeKnown() *big.Int {
	total := big.NewInt(0)
	for _, nsecRange := range wz.knownRanges.Ranges {
		start := nsecRange.Start.toNum()
		end := nsecRange.End.toNum()

		size := end.Sub(end, start)
		total = total.Add(total, size)
	}

	return total
}

func (wz *nsec3WalkZone) sizeUnKnown() *big.Int {
	known := wz.sizeKnown()
	all := nsec3Total()
	return all.Sub(all, known)
}

func (wz *nsec3WalkZone) percentDiscovered() string {
	unknown := wz.sizeKnown()
	unknown = unknown.Mul(unknown, big.NewInt(100_00))

	all := nsec3Total()

	unknown = unknown.Div(unknown, all)
	num := float64(unknown.Int64()) / 100
	return fmt.Sprintf("%.2f%%", num)
}

type hashEntry struct {
	label []byte
	hash  Nsec3Hash
}

func (wz *nsec3WalkZone) addKnown(rn rangeset.RangeEntry[Nsec3Hash], bitmap []uint16) bool {
	if bytes.Compare(rn.Start.H[:], rn.End.H[:]) != -1 {
		// wraparound
		ret := wz.addKnown(rangeset.RangeEntry[Nsec3Hash]{Start: rn.Start, End: nsec3HashEnd}, bitmap)
		wz.addKnown(rangeset.RangeEntry[Nsec3Hash]{Start: nsec3HashStart, End: rn.End}, nil)
		return ret
	}

	if wz.knownRanges.ContainsRange(rn) {
		return false
	}

	wz.knownRanges.Add(rn)

	// do not add nsec3HashStart to known
	if rn.Start == nsec3HashStart {
		return true
	}

	var nsecTypes []string
	for _, t := range bitmap {
		switch t {
		case dns.TypeNSEC3, dns.TypeRRSIG: // skip
		default:
			nsecTypes = append(nsecTypes, dns.Type(t).String())
		}
	}

	wz.rrTypes[rn.Start] = nsecTypes

	return true
}

// assumes sha1 cuz protocol ossification lole
// label is a nsec-formatted label, e.g "\x04abcd", zone is the rest, e.g "\x07example\x03com\x00", salt is decoded salt
// tries to be efficient
func nsec3Hash(label, zone, salt []byte, iterations int) Nsec3Hash {
	h := sha1.New()

	h.Write(label)
	h.Write(zone)
	h.Write(salt)
	hashB := h.Sum(nil)

	for range iterations {
		h.Reset()
		h.Write(hashB)
		h.Write(salt)
		hashB = h.Sum(hashB[:0])
	}

	var ret Nsec3Hash
	copy(ret.H[:], hashB)
	return ret
}

const nsec3walkcharset = "0123456789abcdefghijklmnopqrstuvwxyz"

// generate random (pre-encoded) DNS label for a string matching the pattern ^[0-9a-z]{20,63}$
func randomLabel() []byte {
	length := rand.IntN(63-20) + 20
	ret := make([]byte, length+1)
	ret[0] = byte(length)
	for i := range length {
		ret[i+1] = byte(nsec3walkcharset[rand.IntN(len(nsec3walkcharset))])
	}
	return ret
}

func genHashes(zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	return func(yield func(hashEntry) bool) {
		for {
			label := randomLabel()

			// pick two random different positions in label to permute for batch (aside from length indicator)
			var w, x, y, z int
			w = rand.IntN(len(label)-1) + 1
			x = rand.IntN(len(label)-1) + 1
			y = rand.IntN(len(label)-1) + 1
			z = rand.IntN(len(label)-1) + 1

			for {
				if w == x || w == y || w == z {
					w = rand.IntN(len(label)-1) + 1
					continue
				}
				if x == y || x == z {
					x = rand.IntN(len(label)-1) + 1
					continue
				}
				if y == z {
					y = rand.IntN(len(label)-1) + 1
					continue
				}
				break
			}

			// 36⁴ (1 679 616) entries per batch

			for i := range len(nsec3walkcharset) {
				label[w] = nsec3walkcharset[i]
				for j := range len(nsec3walkcharset) {
					label[x] = nsec3walkcharset[j]
					for k := range len(nsec3walkcharset) {
						label[y] = nsec3walkcharset[k]
						for l := range len(nsec3walkcharset) {
							label[z] = nsec3walkcharset[l]

							hash := nsec3Hash(label, zone, salt, iterations)
							if !yield(hashEntry{
								hash:  hash,
								label: slices.Clone(label[1:]),
							}) {
								return
							}

						}
					}
				}
			}
		}
	}
}

func nsec3Walk(db *sql.DB) {
	readerWriter("performing NSEC3 walks", db, getDbFieldData(`
	SELECT DISTINCT zone.name, zone.id
	FROM name AS zone
	INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
	INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
	WHERE nsec_state.name='nsec3'
	AND zone.nsec_walked=FALSE
	AND zone.inserted=FALSE
`, db), nsec3WalkMaster)
}

func nsec3ParamQuery(connCache connCache, zone string) *dns.NSEC3PARAM {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNSEC3PARAM,
			Name:   zone,
		}},
	}

	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for range RETRIES {
		res, err := plainResolveRandom(msg, connCache)
		if err != nil {
			continue
		}

		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.NSEC3PARAM:
				return rrT
			}
		}
	}

	return nil

}

func nsec3Query(connCache connCache, name string) *dns.Msg {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeAPL,
			Name:   name,
		}},
	}

	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for range RETRIES {
		res, err := plainResolveRandom(msg, connCache)
		if err == nil {
			return res
		}
	}

	return nil
}

func nsec3WalkMaster(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"name":    "name",
		"rr_type": "name",
	}

	namesStmts := map[string]string{
		"nsec3_params": "INSERT OR IGNORE INTO nsec3_zone_params (zone_id, salt, iterations) VALUES (?, ?, ?)",
		"hash":         "INSERT OR IGNORE INTO nsec3_hashes (nsec3_zone_id, nsec3_hash) VALUES ((SELECT id FROM nsec3_zone_params WHERE zone_id=?), ?)",
		// lol...
		"hash_rrtype": "INSERT OR IGNORE INTO nsec3_hash_rr_map (nsec3_hash_id, rr_type_id) VALUES ((SELECT id FROM nsec3_hashes WHERE nsec3_zone_id=(SELECT id FROM nsec3_zone_params WHERE zone_id=?) AND nsec3_hash=?), ?)",
		"set_walked":  "UPDATE name SET nsec_walked=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, nsec3WalkWorker, nsec3WalkInsert)
}

func nsec3WalkWorker(zoneChan <-chan retryWrap[fieldData, empty], refeedChan chan<- retryWrap[fieldData, empty], dataOutChan chan<- nsec3WalkZone, wg, retryWg *sync.WaitGroup) {
	resolverWorker(zoneChan, refeedChan, dataOutChan, dns.Msg{}, nsec3WalkResolve, wg, retryWg)
}

func nsec3WalkInsert(tableMap TableMap, stmtMap StmtMap, zw nsec3WalkZone) {
	zoneID := zw.id

	buf := make([]byte, 32)

	hexSalt := string(hex.AppendEncode(nil, zw.salt))

	stmtMap.exec("nsec3_params", zoneID, hexSalt, zw.iterations)

	for rrName, rrtL := range zw.rrTypes {
		base32.HexEncoding.Encode(buf, rrName.H[:])
		hash := string(buf)

		stmtMap.exec("hash", zoneID, hash)

		for _, rrType := range rrtL {
			rrTypeID := tableMap.get("rr_type", rrType)

			stmtMap.exec("hash_rrtype", zoneID, hash, rrTypeID)
		}
	}

	stmtMap.exec("set_walked", zoneID)
}

func nsec3Compare(v1, v2 Nsec3Hash) int {
	return bytes.Compare(v1.H[:], v2.H[:])
}

const (
	NSEC3_WALK_LIMIT      = 1 << 34
	UNEXPANDED_RUNS_LIMIT = 3
	MIN_DIFF              = 1024
)

var minDiff = big.NewInt(MIN_DIFF)

func nsec3WalkResolve(connCache connCache, _ dns.Msg, zd *retryWrap[fieldData, empty]) (nsec3WalkZone, error) {
	wz := nsec3WalkZone{
		zone:        zd.val.name,
		id:          zd.val.id,
		rrTypes:     make(map[Nsec3Hash][]string),
		knownRanges: rangeset.RangeSet[Nsec3Hash]{Compare: nsec3Compare},
	}

	// fmt.Printf("starting walk on zone %s\n", zone)

	limit := big.NewInt(NSEC3_WALK_LIMIT)

	nsec3Param := nsec3ParamQuery(connCache, wz.zone)
	if nsec3Param == nil {
		return nsec3WalkZone{}, errors.New("unable to fetch NSEC3PARAM")
	}

	wz.salt = check1(hex.AppendDecode(nil, []byte(nsec3Param.Salt)))
	wz.iterations = int(nsec3Param.Iterations)

	var expanded bool
	var unexpanded_runs int

	zoneB := []byte(wz.zone)

	encodedZone := make([]byte, 255)
	off := check1(dns.PackDomainName(wz.zone, encodedZone, 0, nil, false))
	encodedZone = encodedZone[:off]

	for {
		expanded = false
		i := NSEC3_WALK_LIMIT

	hashLoop:
		for guess := range genHashes(encodedZone, wz.salt, wz.iterations) {
			i--
			if i == 0 {
				break
			}

			if wz.contains(guess.hash) {
				continue
			}

			hashName := string(slices.Concat(guess.label, []byte("."), zoneB))

			res := nsec3Query(connCache, hashName)
			if res == nil {
				continue
			}

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					normalizeRR(rrT)
					if soaZone := rrT.Hdr.Name; dnsCompare(wz.zone, soaZone) != 0 && dns.IsSubDomain(wz.zone, soaZone) {
						continue hashLoop
					}
				}
			}

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.NSEC3:
					normalizeRR(rrT)
					if !(rrT.Salt == nsec3Param.Salt && rrT.Iterations == nsec3Param.Iterations) {
						// params changed in the middle of the walk
						return nsec3WalkZone{}, errors.New("nsec3 params changed")
					}

					start, end := nsec3RRToHashes(rrT)

					if labelDiffSmall(start, end) {
						return nsec3WalkZone{}, errors.New("nsec3 white lies?")
					}

					if wz.addKnown(rangeset.RangeEntry[Nsec3Hash]{Start: start, End: end}, rrT.TypeBitMap) {
						expanded = true
					}
				}
			}

			if expanded {
				break
			}
		}

		// got everything already

		fmt.Printf("zone=%s %d ranges %d known names %s zone discovered\n", wz.zone, len(wz.knownRanges.Ranges), len(wz.rrTypes), wz.percentDiscovered())

		if len(wz.knownRanges.Ranges) < 100 {
			fmt.Println(wz.String())
		}

		if len(wz.knownRanges.Ranges) == 1 {
			rn := wz.knownRanges.Ranges[0]
			if rn.Start == nsec3HashStart && rn.End == nsec3HashEnd {
				break
			}
		}

		if expanded {
			unexpanded_runs = 0
			continue
		}

		// quit out early if chance of expanding is unreasonably small
		size := wz.sizeUnKnown()
		if limit.Cmp(size) == 1 {
			break
		}

		unexpanded_runs++
		if unexpanded_runs == UNEXPANDED_RUNS_LIMIT {
			break
		}
	}

	return wz, nil
}
