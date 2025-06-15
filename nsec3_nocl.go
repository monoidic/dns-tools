//go:build !opencl

package main

import "iter"

const hasOpenCL = true

func nsec3HashOpenCLIter(zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	panic("unreachable")
}
