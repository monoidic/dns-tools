//go:build opencl

package main

import (
	"context"
	"slices"
	"unsafe"

	_ "embed"

	cl "github.com/CyberChainXyz/go-opencl"
)

const hasOpenCL = true

//go:embed nsec3.cl
var sha1_cl string

type OpenCLNSEC3In struct {
	Iterations uint16
	LabelLen   uint8
	NameLen    uint8
	SaltLen    uint8
	Name       [255]byte
	Salt       [255]byte
	Indexes    [4]uint8
}

type OpenCLNSEC3Out struct {
	// the rest is known by the receiver anyway
	Hash [20]byte
	Name [63]byte
}

// follow same scheme as nocl variant; 36⁴ = 1679616 names per batch
const OPENCL_ITERATIONS = 36 * 36 * 36 * 36

func initOpenclInfo() {
	// TODO there's probably a more intelligent way of picking a device, or we could let the user decide
	info := check1(cl.Info())
	if len(info.Platforms) == 0 || len(info.Platforms[0].Devices) == 0 {
		// fall back to nocl
		noCL = true
		return
	}

	openclDevice = info.Platforms[0].Devices[0]
}

var openclDevice *cl.OpenCLDevice

func nsec3HashOpenCL(ctx context.Context, zone, salt []byte, iterations int) <-chan hashEntry {
	outCh := make(chan hashEntry, MIDBUFLEN)

	device := openclDevice
	runner := check1(device.InitRunner())

	codes := []string{sha1_cl}
	kernelNameList := []string{"nsec3_main"}

	check(runner.CompileKernels(codes, kernelNameList, ""))

	inEntries := make([]OpenCLNSEC3In, 1)
	inEntry := &inEntries[0]
	copy(inEntry.Salt[:], salt)
	inEntry.SaltLen = uint8(len(salt))
	inEntry.Iterations = uint16(iterations)

	inBuf := check1(cl.CreateBuffer(runner, cl.READ_ONLY|cl.COPY_HOST_PTR, inEntries))
	outBuf := check1(runner.CreateEmptyBuffer(cl.WRITE_ONLY, int(unsafe.Sizeof(OpenCLNSEC3Out{}))*OPENCL_ITERATIONS))
	results := make([]OpenCLNSEC3Out, OPENCL_ITERATIONS)

	go func() {
		defer runner.Free()
		for {
			// strip prefix for... reasons
			label := randomLabel()
			labelLen := len(label) - 1

			copy(inEntry.Name[:], label)
			copy(inEntry.Name[len(label):], zone)
			inEntry.LabelLen = uint8(labelLen)
			inEntry.NameLen = uint8(1 + labelLen + len(zone))

			randNums := nRandNums(1, labelLen, 4)

			for i := range inEntry.Indexes {
				inEntry.Indexes[i] = uint8(randNums[i])
			}

			check(cl.WriteBuffer(runner, 0, inBuf, inEntries, true))
			check(runner.RunKernel("nsec3_main", 1, nil, []uint64{OPENCL_ITERATIONS}, nil, []cl.KernelParam{cl.BufferParam(inBuf), cl.BufferParam(outBuf)}, true))
			check(cl.ReadBuffer(runner, 0, outBuf, results))

			for _, outEntry := range results {
				entry := hashEntry{
					label: slices.Clone(outEntry.Name[:labelLen]),
					hash:  Nsec3Hash{outEntry.Hash},
				}

				select {
				case outCh <- entry:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return outCh
}
