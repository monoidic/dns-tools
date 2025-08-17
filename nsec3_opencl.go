//go:build opencl

package main

import (
	"context"
	"sync"
	"unsafe"

	_ "embed"

	cl "github.com/CyberChainXyz/go-opencl"
)

const hasOpenCL = true

//go:embed nsec3.cl
var sha1_cl string

type OpenCLNSEC3In struct {
	Iterations uint16
	NameLen    uint8
	SaltLen    uint8
	Name       [255]byte
	Salt       [255]byte
	Indexes    [3]uint8
}

type OpenCLNSEC3Out struct {
	// the rest is known by the receiver anyway
	Hash [20]byte
}

// follow similar scheme to nocl variant; 36³ = 46656 names per batch
const OPENCL_ITERATIONS = 36 * 36 * 36

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
	const NUM_WORKERS = 8
	var wg sync.WaitGroup
	wg.Add(NUM_WORKERS)
	closeChanWait(&wg, outCh)

	for range NUM_WORKERS {
		go nsec3HashOpenCLInner(ctx, zone, salt, iterations, outCh, &wg)
	}

	return outCh
}

func nsec3HashOpenCLInner(ctx context.Context, zone, salt []byte, iterations int, outCh chan hashEntry, wg *sync.WaitGroup) {
	defer wg.Done()

	runner := check1(openclDevice.InitRunner())
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

	defer runner.Free()
	for {
		label := randomLabel()
		labelLen := len(label) - 1

		copy(inEntry.Name[:], label)
		copy(inEntry.Name[len(label):], zone)
		inEntry.NameLen = uint8(1 + labelLen + len(zone))

		randNums := nRandNums(1, labelLen, len(inEntry.Indexes))

		for i := range inEntry.Indexes {
			inEntry.Indexes[i] = uint8(randNums[i])
		}

		check(cl.WriteBuffer(runner, 0, inBuf, inEntries, true))
		check(runner.RunKernel("nsec3_main", 1, nil, []uint64{OPENCL_ITERATIONS}, nil, []cl.KernelParam{cl.BufferParam(inBuf), cl.BufferParam(outBuf)}, true))
		check(cl.ReadBuffer(runner, 0, outBuf, results))

		for i, outEntry := range results {
			entry := hashEntry{
				construct: true,
				label:     label,
				idx:       i,
				indexes:   inEntry.Indexes,
				hash:      Nsec3Hash{outEntry.Hash},
			}

			select {
			case outCh <- entry:
			case <-ctx.Done():
				return
			}
		}
	}
}
