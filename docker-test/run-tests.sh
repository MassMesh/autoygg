#!/bin/bash
set -euo pipefail

yggdrasil -autoconf &
YGG_PID=$!

cd /autoygg/internal
go version
go test

kill $!
