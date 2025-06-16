//go:build !opencl

package main

const hasOpenCL = false

func nsec3HashOpenCL(zone, salt []byte, iterations int) (ch <-chan hashEntry, cancel func()) {
	panic("unreachable")
}
