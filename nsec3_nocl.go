//go:build !opencl

package main

const hasOpenCL = false

var openclDevice *empty

func initOpenclInfo() {}

func nsec3HashOpenCL(zone, salt []byte, iterations int) (ch <-chan hashEntry, cancel func()) {
	panic("unreachable")
}
