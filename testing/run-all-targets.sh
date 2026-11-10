#!/bin/sh
# Lints every file and runs the tests (testing/main.php) on every supported NftablesTarget, each in its own throwaway
# Docker container with that operating system's own nft. This checks the JSON loads on the oldest nft supported, and
# that the features which need a newer one are refused for the targets that can't load them (see CompatibilityTest).
# Each image is defined in testing/targets/<TARGET>.Dockerfile, named after the NftablesTarget case it tests.
#
# Usage:
#   testing/run-all-targets.sh                         # test every target
#   testing/run-all-targets.sh DEBIAN_11 UBUNTU_22_04  # test only these targets
#   testing/run-all-targets.sh --rebuild               # rebuild the Docker images first
#
# Requires Docker, and "composer install" to have been run, as the tests use the vendor/ directory.
# Exits with 0 if every target passed, or 1 if any failed.
#
# As in run-all-php-versions.sh, the containers run without Docker's seccomp profile, which blocks the unshare the nft
# tests use to give each test its own network namespace. Containers share the host's kernel, so this tests each
# target's nft, but not its kernel.

scriptDir=$(cd "$(dirname "$0")" && pwd)
repoDir=$(dirname "$scriptDir")
rebuild=0
targets=""

for arg in "$@"
do
    if [ "$arg" = "--rebuild" ]
    then
        rebuild=1
    else
        targets="$targets $arg"
    fi
done

if [ -z "$targets" ]
then
    for dockerfile in "$scriptDir"/targets/*.Dockerfile
    do
        targets="$targets $(basename "$dockerfile" .Dockerfile)"
    done
fi

if [ ! -f "$repoDir/vendor/autoload.php" ]
then
    echo "vendor/autoload.php is missing. Please run \"composer install\" first."
    exit 1
fi

failedTargets=""

for target in $targets
do
    image="nftables-target-$(echo "$target" | tr 'A-Z_' 'a-z-')"
    echo
    echo "################ ${target}"

    if [ "$rebuild" -eq 1 ] || ! docker image inspect "$image" > /dev/null 2>&1
    then
        echo "building ${image}..."

        if ! docker build -q --pull -t "$image" -f "$scriptDir/targets/${target}.Dockerfile" "$scriptDir/targets" > /dev/null
        then
            echo "FAILED to build the image for ${target}"
            failedTargets="$failedTargets $target"
            continue
        fi
    fi

    if ! docker run --rm -v "$repoDir":/src:ro -w /src \
        --security-opt seccomp=unconfined \
        -e NFTABLES_TEST_REQUIRE_NFT=1 \
        -e NFTABLES_TEST_TARGET="$target" \
        "$image" sh /src/testing/php-versions/run-in-container.sh
    then
        failedTargets="$failedTargets $target"
    fi
done

echo
if [ -z "$failedTargets" ]
then
    echo "All passed:" $targets
    exit 0
else
    echo "FAILED on:" $failedTargets
    exit 1
fi
