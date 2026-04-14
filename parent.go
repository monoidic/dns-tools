package main

import (
	"database/sql"
	"iter"

	"github.com/monoidic/dns"
)

type childParent struct {
	childID     int64
	parentGuess dns.Name
	realParent  dns.Name
	resolved    bool
}

func nameParents(name dns.Name) []dns.Name {
	if name == rootName {
		return nil
	}

	ret := name.SubNames()
	ret = append(ret, rootName)
	return ret
}

func mapZoneParentsPre(db *sql.DB) {
	readerWriter("mapping zone parents prework", db, getDbNameData(`
	SELECT zone.name, zone.id
	FROM name AS zone
	WHERE zone.parent_mapped=FALSE
	AND zone.registered=TRUE AND zone.valid=TRUE
`, db), mapZoneParentsPreWriter)
}

func mapZoneParentsPreWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":            "name",
		"parent_map_name": "name",
	}

	namesStmts := map[string]string{
		"add_guess":   "INSERT OR IGNORE INTO parent_map (child_id, parent_id) VALUES (?, ?)",
		"name_parent": "UPDATE name SET parent_id=?, parent_mapped=TRUE WHERE id=?",
		"add_zone":    "UPDATE name SET is_zone=TRUE WHERE id=?",
	}

	childParents := addChildParent(seq)

	netWriterTable(db, childParents, tablesFields, namesStmts, parentCheckPreWorker, parentCheckPreWriter)
}

func mapZoneParents(db *sql.DB) {
	readerWriter("mapping zone parents", db, getDbNameData(`
	SELECT name, id
	FROM parent_map_name
`, db), parentCheck)
}

func parentCheck(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name": "name",
	}

	namesStmts := map[string]string{
		"set_zone":    "UPDATE name SET is_zone=TRUE WHERE id=?",
		"mapped_null": "UPDATE name SET parent_mapped=TRUE FROM (SELECT child_id FROM parent_map WHERE parent_id=?) AS c WHERE name.id=c.child_id",
		"mapped":      "UPDATE name SET parent_mapped=TRUE, parent_id=? FROM (SELECT child_id FROM parent_map WHERE parent_id=?) AS c WHERE name.id=c.child_id",
		"name_parent": "UPDATE name SET parent_id=? WHERE id=?",

		"clean_parent_map":      "DELETE FROM parent_map WHERE parent_id=?",
		"clean_parent_map_name": "DELETE FROM parent_map_name WHERE id=?",
	}

	netWriterTable(db, seq, tablesFields, namesStmts, parentCheckWorker, parentCheckWriter)
}

func addChildParent(seq iter.Seq[nameData]) iter.Seq[childParent] {
	return func(yield func(childParent) bool) {
		for fd := range seq {
			cp := childParent{childID: fd.id}

			if parents := nameParents(fd.name); len(parents) >= 2 {
				cp.parentGuess = parents[1]
			} else {
				cp.parentGuess = rootName
			}

			if !yield(cp) {
				return
			}
		}
	}
}

func parentCheckWriter(tsm *TableStmtMap, res childParent) {
	defer func() {
		tsm.exec("clean_parent_map", res.childID)
		tsm.exec("clean_parent_map_name", res.childID)
	}()
	if !res.resolved {
		tsm.exec("mapped_null", res.childID)
		return
	}

	parentID := tsm.get("name", res.realParent.String())

	tsm.exec("mapped", parentID, res.childID)
	tsm.exec("set_zone", parentID)
	tsm.exec("name_parent", parentID, res.childID)
}

func parentCheckPreWriter(tsm *TableStmtMap, cp childParent) {
	guessID := cp.childID
	parentGuess := cp.parentGuess.String()
	parentID := tsm.roGet("name", parentGuess)
	if parentID != 0 {
		// already exists
		tsm.exec("name_parent", parentID, guessID)
		tsm.exec("add_zone", parentID)
		return
	}
	// does not exist, add to parent_map for full parent_check
	parentID = tsm.get("parent_map_name", parentGuess)
	tsm.exec("add_guess", guessID, parentID)
}
