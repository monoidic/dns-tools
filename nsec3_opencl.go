//go:build opencl

package main

import (
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
	ZoneLen    uint8
	SaltLen    uint8
	Zone       [255]byte
	Label      [63]byte
	Salt       [255]byte
	Indexes    [4]uint8
}

type OpenCLNSEC3Out struct {
	// known by receiver anyway
	Hash [20]byte
	Name [63]byte
}

// follow same scheme as nocl variant; 36⁴ = 1679616 names per batch
const OPENCL_ITERATIONS = 36 * 36 * 36 * 36

func nsec3HashOpenCL(zone, salt []byte, iterations int) (ch <-chan hashEntry, cancel func()) {
	outCh := make(chan hashEntry, MIDBUFLEN)
	cancelCh := make(chan empty)
	cancel = func() { close(cancelCh) }

	info := check1(cl.Info())
	device := info.Platforms[0].Devices[0]
	runner := check1(device.InitRunner())

	codes := []string{sha1_cl}
	kernelNameList := []string{"nsec3_main"}

	check(runner.CompileKernels(codes, kernelNameList, ""))

	inEntries := make([]OpenCLNSEC3In, 1)
	copy(inEntries[0].Salt[:], salt)
	copy(inEntries[0].Zone[:], zone)
	inEntries[0].SaltLen = uint8(len(salt))
	inEntries[0].ZoneLen = uint8(len(zone))
	inEntries[0].Iterations = uint16(iterations)

	inBuf := check1(cl.CreateBuffer(runner, cl.READ_ONLY|cl.COPY_HOST_PTR, inEntries))
	outBuf := check1(runner.CreateEmptyBuffer(cl.WRITE_ONLY, int(unsafe.Sizeof(OpenCLNSEC3Out{}))*OPENCL_ITERATIONS))
	results := make([]OpenCLNSEC3Out, OPENCL_ITERATIONS)

	go func() {
		defer runner.Free()
		for {
			// strip prefix for... reasons
			label := randomLabel()[1:]
			copy(inEntries[0].Label[:], label)
			inEntries[0].LabelLen = uint8(len(label))

			randNums := nRandNums(1, len(label), 4)

			for i := range inEntries[0].Indexes {
				inEntries[0].Indexes[i] = uint8(randNums[i])
			}

			check(cl.WriteBuffer(runner, 0, inBuf, inEntries, true))
			check(runner.RunKernel("nsec3_main", 1, nil, []uint64{OPENCL_ITERATIONS}, nil, []cl.KernelParam{cl.BufferParam(inBuf), cl.BufferParam(outBuf)}, true))
			check(cl.ReadBuffer(runner, 0, outBuf, results))

			outLabelLen := len(label)

			for _, outEntry := range results {
				entry := hashEntry{
					label: slices.Clone(outEntry.Name[:outLabelLen]),
					hash:  Nsec3Hash{outEntry.Hash},
				}

				select {
				case outCh <- entry:
				case <-cancelCh:
					return
				}
			}
		}
	}()

	return outCh, cancel
}
