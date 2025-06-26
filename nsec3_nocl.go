//go:build !opencl

package main

import "context"

const hasOpenCL = false

var openclDevice *empty

func initOpenclInfo() {}

func nsec3HashOpenCL(ctx context.Context, zone, salt []byte, iterations int) <-chan hashEntry {
	panic("unreachable")
}
