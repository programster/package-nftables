#!/bin/sh
# Lints every file and runs the tests (testing/main.php) on every supported version of PHP, each in its own throwaway
# Docker container, then runs PHPStan once. This catches code that only works on newer versions of PHP than the minimum
# this package supports.
#
# Usage:
#   testing/run-all-php-versions.sh                # test every supported version
#   testing/run-all-php-versions.sh 8.2 8.5        # test only these versions
#   testing/run-all-php-versions.sh --rebuild      # rebuild the Docker images first (e.g. to get the latest patch release)
#
# Requires Docker, and "composer install" to have been run, as the tests use the vendor/ directory.
# Exits with 0 if every version passed, or 1 if any failed.
#
# The tests that load rulesets into real nft run each test in its own network namespace (unshare -rn). Docker's default
# seccomp profile blocks unshare, so the containers are run without it. That only loosens the throwaway test
# container, and the namespaces still keep every rule away from the host's (and the container's) own firewall.

SUPPORTED_VERSIONS="8.2 8.3 8.4 8.5"

scriptDir=$(cd "$(dirname "$0")" && pwd)
repoDir=$(dirname "$scriptDir")
rebuild=0
versions=""

for arg in "$@"
do
    if [ "$arg" = "--rebuild" ]
    then
        rebuild=1
    else
        versions="$versions $arg"
    fi
done

if [ -z "$versions" ]
then
    versions=$SUPPORTED_VERSIONS
fi

if [ ! -f "$repoDir/vendor/autoload.php" ]
then
    echo "vendor/autoload.php is missing. Please run \"composer install\" first."
    exit 1
fi

failedVersions=""
phpstanFailed=0

for version in $versions
do
    image="nftables-php${version}-test"
    echo
    echo "################ PHP ${version}"

    if [ "$rebuild" -eq 1 ] || ! docker image inspect "$image" > /dev/null 2>&1
    then
        echo "building ${image}..."

        if ! docker build -q --pull --build-arg PHP_VERSION="$version" -t "$image" "$scriptDir/php-versions" > /dev/null
        then
            echo "FAILED to build the image for PHP ${version}"
            failedVersions="$failedVersions $version"
            continue
        fi
    fi

    # NFTABLES_TEST_REQUIRE_NFT makes a skipped nft test a failure, as nft is always available in these containers.
    if ! docker run --rm -v "$repoDir":/src:ro -w /src \
        --security-opt seccomp=unconfined \
        -e NFTABLES_TEST_REQUIRE_NFT=1 \
        "$image" sh /src/testing/php-versions/run-in-container.sh
    then
        failedVersions="$failedVersions $version"
    fi
done

# Static analysis only needs to run once. It runs on the lowest version tested, as that is the most likely to differ.
# It needs no network access, or nft, so it runs with the network switched off and Docker's default seccomp profile.
lowestVersion=$(echo $versions | tr ' ' '\n' | sort -V | head -n 1)
echo
echo "################ PHPStan (PHP ${lowestVersion})"

if ! docker run --rm --network none -v "$repoDir":/src:ro "nftables-php${lowestVersion}-test" \
    sh -c 'cp -r /src /app && cd /app && php vendor/bin/phpstan --no-progress --memory-limit=1G'
then
    phpstanFailed=1
fi

echo
if [ -z "$failedVersions" ] && [ "$phpstanFailed" -eq 0 ]
then
    echo "All passed:" $versions
    exit 0
else
    [ -z "$failedVersions" ] || echo "FAILED on PHP:" $failedVersions
    [ "$phpstanFailed" -eq 0 ] || echo "FAILED PHPStan"
    exit 1
fi
