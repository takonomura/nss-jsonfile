#!/bin/bash
set -euo pipefail

TARGET="${TARGET:-$PWD/target/x86_64-unknown-linux-gnu/release/libnss_jsonfile.so}"
if ! [ -e "$TARGET" ]; then
  echo "$TARGET is not found"
  exit 1
fi

if [ -z "${DOCKER:-}" ]; then
  if which docker >/dev/null 2>&1; then
    DOCKER=docker
  elif which podman >/dev/null 2>&1; then
    DOCKER=podman
  elif which nerdctl >/dev/null 2>&1; then
    DOCKER=nerdctl
  else
    echo "No docker compatible command detected"
    exit 1
  fi
  echo "Using $DOCKER"
fi

$DOCKER pull docker.io/library/debian:buster
$DOCKER pull docker.io/library/centos:7

failed=0

function assert_result() {
  echo -n "$1: "
  if [ "$2" = "$3" ]; then
    echo "success"
  else
    echo "failed"
    echo "  expected: $3"
    echo "       got: $2"
    failed=$(( failed + 1 ))
  fi
}

function test_case() {
  local result="$($DOCKER run --rm \
    --volume "$PWD/examples/passwd.json":/etc/passwd.json:ro \
    --volume "$PWD/examples/group.json":/etc/group.json:ro \
    --volume "$TARGET":/lib/x86_64-linux-gnu/libnss_jsonfile.so.2:ro \
    docker.io/library/debian:buster \
    sh -c "$2")"
  assert_result "$1" "$result" "$3"
}

test_case \
  "Get testuser1" \
  "getent -s jsonfile passwd testuser1" \
  "testuser1:*:2001:2001::/home/testuser:/bin/bash"

test_case \
  "Get testuser2" \
  "getent -s jsonfile passwd testuser2" \
  "testuser2::2002:9999:test user:/home/testuser2:/bin/bash"

test_case \
  "Get non-existent user" \
  "getent -s jsonfile passwd notexistuser" \
  ""

test_case \
  "Get auto-created group for testuser1" \
  "getent -s jsonfile group testuser1" \
  "testuser1:*:2001:"

test_case \
  "Get non-existent group for testuser2" \
  "getent -s jsonfile group testuser2" \
  ""

test_case \
  "Get testgroup1" \
  "getent -s jsonfile group testgroup1" \
  "testgroup1:*:9999:"

test_case \
  "Get testgroup2" \
  "getent -s jsonfile group testgroup2" \
  "testgroup2::9998:testuser1"

test_case \
  "Get non-existent group" \
  "getent -s jsonfile group notexistgroup" \
  ""

test_case \
  "Get groups for testuser1" \
  "getent -s jsonfile initgroups testuser1" \
  "testuser1             9998 9999"

test_case \
  "Get groups for testuser2" \
  "getent -s jsonfile initgroups testuser2" \
  "testuser2            "

test_case \
  "Get groups for non-existent user" \
  "getent -s jsonfile initgroups notexistuser" \
  "notexistuser         "

assert_result \
  "Get testuser1 on CentOS 7" \
  "$($DOCKER run --rm \
    --volume "$PWD/examples/passwd.json":/etc/passwd.json:ro \
    --volume "$TARGET":/usr/lib64/libnss_jsonfile.so.2:ro \
    docker.io/library/centos:7 \
    sh -c "getent -s jsonfile passwd testuser1")" \
  "testuser1:*:2001:2001::/home/testuser:/bin/bash"

if [ $failed -ne 0 ]; then
  echo "$failed failed tests"
  exit 1
fi
