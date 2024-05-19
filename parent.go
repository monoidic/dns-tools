package main

import (
	"database/sql"
	"iter"

	"github.com/miekg/dns"
)

type childParent struct {
	child       fieldData
	parent      fieldData
	parentGuess string
	resolved    bool
	registered  bool
}

// modified from miekg/dns Split() to return strings and the root zone (".")
func nameParents(name string) []string {
	name = dns.Fqdn(name)

	if name == "." {
		return []string{}
	}

	var idx []int
	off := 0

	for end := false; !end; off, end = dns.NextLabel(name, off) {
		idx = append(idx, off)
	}

	idx = append(idx, off-1)

	ret := make([]string, 0, len(idx))
	for _, i := range idx[1:] {
		ret = append(ret, name[i:])
	}

	return ret
}

func mapZoneParents(db *sql.DB) {
	readerWriter("mapping zone parents", db, getDbFieldData(`
	SELECT name, id
	FROM name
	WHERE
	parent_mapped=FALSE
	AND valid=TRUE
`, db), parentCheck)
}

func parentCheck(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"name": "name",
	}

	namesStmts := map[string]string{
		"set_zone":    "UPDATE name SET is_zone=TRUE WHERE id=?",
		"mapped":      "UPDATE name SET parent_mapped=TRUE WHERE id=?",
		"name_parent": "UPDATE name SET parent_id=? WHERE id=?",
	}

	childParents := addChildParent(seq)

	netWriterTable(db, childParents, tablesFields, namesStmts, parentCheckWorker, parentCheckWriter)
}

func addChildParent(seq iter.Seq[fieldData]) iter.Seq[childParent] {
	return func(yield func(childParent) bool) {
		for fd := range seq {
			cp := childParent{child: fd}

			if parents := nameParents(fd.name); len(parents) > 0 {
				cp.parentGuess = parents[0]
			}

			if !yield(cp) {
				return
			}
		}
	}
}

func parentCheckWriter(tableMap TableMap, stmtMap StmtMap, res childParent) {
	if res.resolved && res.parentGuess != "" {
		parentID := res.parent.id

		if parentID == 0 {
			name := res.parentGuess
			if res.registered {
				name = res.parent.name
			}
			parentID = tableMap.get("name", name)
		}

		stmtMap.exec("set_zone", parentID)
		stmtMap.exec("name_parent", parentID, res.child.id)

	}

	stmtMap.exec("mapped", res.child.id)
}
