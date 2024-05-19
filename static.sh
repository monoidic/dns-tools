#!/bin/sh

apk add alpine-sdk go sqlite-dev
GOEXPERIMENT=rangefunc go build -C src -tags netgo,sqlite_omit_load_extension -trimpath -ldflags="-s -w -extldflags=-static" -buildmode=pie
