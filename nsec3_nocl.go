//go:build !opencl

package main

import "iter"

const hasOpenCL = false

func nsec3HashOpenCLIter(zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	panic("unreachable")
}
