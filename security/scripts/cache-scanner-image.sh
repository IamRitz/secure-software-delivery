#!/usr/bin/env bash
# Make a pinned scanner image available locally without re-pulling it every run.
#
# On a cache HIT (the tarball is already present in the cache dir) the image is
# restored with `docker load` and given the stable local tag it was saved under.
# On a cache MISS the image is pulled BY DIGEST (so the content is verified
# against the pin), tagged with the same local tag, and saved for next time.
#
# The digest is what keys the CI cache, so a pin bump is a cache miss and forces
# a fresh, digest-verified pull. The local tag exists only because `docker load`
# does not restore a manifest digest reference (RepoDigests), so `docker run
# <ref>@sha256:...` after a load would otherwise re-pull. Callers therefore run
# the scanner by the local tag; the content is still exactly the pinned image.
#
# Usage: cache-scanner-image.sh <cache-dir> <image@sha256:digest> <local-tag>
set -euo pipefail

dir="$1"
ref="$2"
tag="$3"

if [ -z "$dir" ] || [ -z "$ref" ] || [ -z "$tag" ]; then
  echo "usage: cache-scanner-image.sh <cache-dir> <image@sha256:digest> <local-tag>" >&2
  exit 2
fi

case "$ref" in
  *@sha256:*) : ;;
  *)
    echo "refusing to cache '$ref': image must be pinned by @sha256 digest" >&2
    exit 2
    ;;
esac

mkdir -p "$dir"
tar="$dir/$(printf '%s' "$tag" | tr '/:' '__').tar"

if [ -f "$tar" ]; then
  echo "cache hit: loading $tag from $tar"
  docker load -i "$tar"
else
  echo "cache miss: pulling $ref by digest"
  docker pull "$ref"
  docker tag "$ref" "$tag"
  docker save "$tag" -o "$tar"
  echo "saved $tag to $tar for the next run"
fi
