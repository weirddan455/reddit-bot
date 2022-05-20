#!/bin/sh

set -o errexit

root_dir_path="$(dirname -- "$0")"

"${CC:-cc}" "$root_dir_path/reddit.c" -lcurl -o "$root_dir_path/reddit" -O3 -Wall
