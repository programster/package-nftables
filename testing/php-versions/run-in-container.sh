#!/bin/sh
# Runs inside each test container (see testing/run-all-php-versions.sh): lints every file, then runs the tests.
# Exits with 1 if anything fails to lint, or any test fails.

failed=0
echo "PHP $(php -r 'echo PHP_VERSION;'): linting..."

for file in $(find /src/src /src/testing -name "*.php")
do
    if ! output=$(php -l "$file" 2>&1)
    then
        # php -l starts its message with a blank line, and ends it with "Errors parsing <file>".
        echo "  FAIL lint: $(echo "$output" | grep -v -e '^$' -e '^Errors parsing' | head -1)"
        failed=1
    fi
done

if ! php /src/testing/main.php
then
    failed=1
fi

exit $failed
