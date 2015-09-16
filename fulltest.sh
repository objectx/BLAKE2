#! /bin/sh

[ -d BUILD ] && rm -rf BUILD

mkdir BUILD

(cd BUILD && cmake -G Ninja .. && cmake --build .)

./BUILD/bin/test-blake2 -r compact
