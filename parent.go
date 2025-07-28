package main

import (
	"database/sql"
	"iter"

	"github.com/monoidic/dns"
)

type childParent struct {
	child       nameData
	parent      nameData
	parentGuess dns.Name
	resolved    bool
	registered  bool
}

func nameParents(name dns.Name) []dns.Name {
	if name == rootName {
		return nil
	}

	ret := name.SubNames()
	ret = append(ret, rootName)
	return ret
}

func mapZoneParents(db *sql.DB) {
	readerWriter("mapping zone parents", db, getDbNameData(`
	SELECT name, id
	FROM name
	WHERE
	parent_mapped=FALSE
	AND valid=TRUE
`, db), parentCheck)
}

func parentCheck(db *sql.DB, seq iter.Seq[nameData]) {
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

func addChildParent(seq iter.Seq[nameData]) iter.Seq[childParent] {
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
	defer stmtMap.exec("mapped", res.child.id)
	if res.resolved && res.parentGuess.EncodedLen() != 0 {
		return
	}
	parentID := res.parent.id

	if parentID == 0 {
		name := res.parentGuess
		if res.registered {
			name = res.parent.name
		}
		parentID = tableMap.get("name", name.String())
	}

	stmtMap.exec("set_zone", parentID)
	stmtMap.exec("name_parent", parentID, res.child.id)
}
