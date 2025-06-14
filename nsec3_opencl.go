package main

import (
	"iter"
	"unsafe"

	_ "embed"

	cl "github.com/CyberChainXyz/go-opencl"
)

//go:embed nsec3.cl
var sha1_cl string

type OpenCLNSEC3In struct {
	NameLen    uint8
	SaltLen    uint8
	Iterations uint16
	Name       [255]byte
	Salt       [255]byte
}

type OpenCLNSEC3Out struct {
	NameLen uint8
	Hash    [20]byte
	Name    [255]byte
}

func (ret *OpenCLNSEC3In) inits(salt []byte, iterations int) {
	ret.SaltLen = uint8(len(salt))
	ret.Iterations = uint16(iterations)

	copy(ret.Salt[:], salt)
}

func (oin *OpenCLNSEC3In) setName(label, zone []byte) {
	oin.NameLen = uint8(len(label) + len(zone))
	copy(oin.Name[:], label)
	copy(oin.Name[len(label):], zone)
}

const OPENCL_BUF_SIZE = 1024 * 1024

func nsec3HashOpenCL(zone, salt []byte, iterations int) (ch <-chan hashEntry, cancel func()) {
	outCh := make(chan hashEntry, 1024)
	cancelCh := make(chan empty)
	cancel = func() { close(cancelCh) }

	info := check1(cl.Info())
	device := info.Platforms[0].Devices[0]
	runner := check1(device.InitRunner())

	codes := []string{sha1_cl}
	kernelNameList := []string{"nsec3_main"}

	check(runner.CompileKernels(codes, kernelNameList, ""))

	inEntries := make([]OpenCLNSEC3In, OPENCL_BUF_SIZE)

	for i := range inEntries {
		// set salt and iterations
		inEntries[i].inits(salt, iterations)
	}

	inBuf := check1(cl.CreateBuffer(runner, cl.READ_ONLY|cl.COPY_HOST_PTR, inEntries))
	outBuf := check1(runner.CreateEmptyBuffer(cl.WRITE_ONLY, int(unsafe.Sizeof(OpenCLNSEC3Out{}))*len(inEntries)))

	go func() {
		defer runner.Free()
		for {
			var i int

			for label := range randomLabels {
				inEntries[i].setName(label, zone)
				i++
				if i >= len(inEntries) {
					break
				}
			}

			check(cl.WriteBuffer(runner, 0, inBuf, inEntries, true))

			check(runner.RunKernel("nsec3_main", 1, nil, []uint64{uint64(len(inEntries))}, nil, []cl.KernelParam{cl.BufferParam(inBuf), cl.BufferParam(outBuf)}, true))

			results := make([]OpenCLNSEC3Out, len(inEntries))
			check(cl.ReadBuffer(runner, 0, outBuf, results))

			for _, outEntry := range results {
				labelLen := outEntry.Name[0]
				label := outEntry.Name[1 : labelLen+1]
				select {
				case outCh <- hashEntry{
					label: label,
					hash:  Nsec3Hash{outEntry.Hash},
				}:
				case <-cancelCh:
					return
				}
			}
		}
	}()

	return outCh, cancel
}

func nsec3HashOpenCLIter(zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	ch, cancel := nsec3HashOpenCL(zone, salt, iterations)
	return func(yield func(hashEntry) bool) {
		defer cancel()
		for e := range ch {
			if !yield(e) {
				return
			}
		}
	}
}
