#!/usr/bin/env bash
if test $(${GO:-go} env GOOS) != "linux" ; then
	exit 0
fi
tmpdir="$PWD/tmp.$RANDOM"
mkdir -p "$tmpdir"
trap 'rm -fr "$tmpdir"' EXIT
cc -o "$tmpdir"/libsubid_tag -l composefs -l yajl -x c - > /dev/null 2> /dev/null << EOF
#include <libcomposefs/lcfs-mount.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	return 0;
}
EOF
if test $? -eq 0 ; then
	echo composefs
fi
