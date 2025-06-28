#!/bin/sh
RUSTFLAGS="-Ctarget-cpu=native" cargo bench -F _bench
