# Testing

- [Running the tests](#running-the-tests)
- [Testing every supported PHP version](#testing-every-supported-php-version)
- [Testing every target](#testing-every-target)
- [Running some of the tests](#running-some-of-the-tests)
- [Continuous integration](#continuous-integration)
- [Writing tests](#writing-tests)

## Running the tests
Run `composer install`, and then:

```bash
composer test    # or: php testing/main.php
```

The tests are plain PHP scripts in `testing/tests/`, with no test framework. A test fails if it throws, fails a check,
or raises a PHP warning or deprecation. The run exits with a non-zero code if anything fails, and lists anything it had
to skip, and why.

They include:

- **The structure of the JSON** each class produces, without needing nft.
- **Every check that rejects bad input**, and the bugs fixed in 1.0.
- **Every feature, loaded into real nft**, comparing nft's own listing of it with what it should be. Each of these runs
  in a throwaway network namespace (`unshare -rn`), so it needs no root and never touches the machine's own rules.
  They're skipped where nft, the `ip` command (from iproute2, for the network devices the flowtable tests use) or
  unprivileged user namespaces aren't available.
- **The features that need a newer nft** than the oldest supported (see [targets](targets.md)), which must be
  refused for the targets that can't load them, and load for the ones that can (`CompatibilityTest.php`).
- **The examples in the docs and README**, which are run, with their nft listings checked against nft, so the docs
  can't drift from what the code does.

Every ruleset the tests load is also checked to have loaded completely: nft drops some things it doesn't understand
without an error (e.g. a table's flags), so a load succeeding isn't enough on its own.

## Testing every supported PHP version
The package supports PHP 8.2 and above. To check every supported version, run the following, which tests each in its
own throwaway Docker container. Use it before releasing, as it catches code that only works on newer versions than
the minimum.

```bash
testing/run-all-php-versions.sh             # every supported version (8.2, 8.3, 8.4 and 8.5)
testing/run-all-php-versions.sh 8.2 8.5     # only these versions
testing/run-all-php-versions.sh --rebuild   # rebuild the images first, to get the latest PHP patch releases
```

For each version, it lints every file, then runs the tests. The images (`php:<version>-cli` with nft added) are built
the first time they're needed, and then reused. When a new version of PHP is released, add it to
`SUPPORTED_VERSIONS` at the top of the script.

Docker's default seccomp profile blocks `unshare`, so the containers run without it
(`--security-opt seccomp=unconfined`). That only loosens the throwaway container, and the network namespaces still
keep every rule away from the host's firewall (and the container's own). The containers also set
`NFTABLES_TEST_REQUIRE_NFT=1`, which turns a skipped nft test into a failure, as nft is always available there.

## Testing every target
The rulesets are loaded on servers with all sorts of nft versions, so the tests also run on every
[target](targets.md), each in a throwaway Docker container with that operating system's own nft:

```bash
testing/run-all-targets.sh                          # every target (Debian 11 to 13, Ubuntu 22.04 to 26.04, Rocky Linux 8 to 10)
testing/run-all-targets.sh DEBIAN_11 UBUNTU_22_04   # only these targets
testing/run-all-targets.sh --rebuild                # rebuild the images first
```

Each image is defined in `testing/targets/<TARGET>.Dockerfile`, named after the `NftablesTarget` it tests, and the
script sets `NFTABLES_TEST_TARGET` to that name, so the tests know which target they're checking. Some of the oldest
releases' own PHP is too old for the package, so their images add PHP 8.2 alongside the release's own nft. To support
a new release, add a target for it to `NftablesTarget`, and a Dockerfile here.

Older versions of nft word some of their listings differently (e.g. `queue num 0` for `queue to 0`), so on nft before
1.1 the tests check everything loads completely, but don't compare nft's wording with the docs. Without
`NFTABLES_TEST_TARGET`, the tests work out the target from `nft --version`.

## Running some of the tests
Set `NFTABLES_TEST_ONLY` to run only the tests whose name contains it. It fails if no test matches, so a typo can't
pass without checking anything:

```bash
NFTABLES_TEST_ONLY="nft:" composer test         # only the tests that load into nft
NFTABLES_TEST_ONLY="Validation" composer test   # only the input checks
```

## Continuous integration
`.github/workflows/tests.yml` runs `testing/run-all-php-versions.sh` and `testing/run-all-targets.sh`, as two jobs, on
pushes to `main`, on every tag, and on pull requests into `main`. It can also be run by hand on any branch, with "Run
workflow" on the repository's Actions tab. The badge at the top of the README shows the result of the latest run on
`main`.

GitHub's Ubuntu runners block unprivileged user namespaces with AppArmor, so the workflow allows them first. The
runner is thrown away after each run.

## Writing tests
Add a test to the file for its area in `testing/tests/`, or create a new `*Test.php` file there, which `main.php`
picks up automatically. Each file is given `$smoke` (the runner) and `$dir` (a temporary directory, deleted
afterwards). Assign each test to a named closure, then run it:

```php
$testDefaultResetMode = function () : void {
    $ruleset = new Ruleset();
    SmokeTestRunner::assertSame(RulesetResetMode::REPLACE_OWN_TABLES, $ruleset->getResetMode(), "the default mode");
};

$smoke->run("Ruleset: the default reset mode replaces its own tables", $testDefaultResetMode);
```

The checks are `SmokeTestRunner::assertSame()`, `assertTrue()`, `assertContains()` and `expectException()`. They throw
when they fail, rather than using `assert()`, so they work whatever `zend.assertions` is set to.

For a test against real nft, use `NftNamespace::loadAndList()`, which loads a ruleset into a fresh namespace and gives
nft's listing of it (see `FeaturesNftTest.php`). Doc examples need no test of their own: `DocsTest.php` runs every
`php` block in the docs, in order, and checks each `nft` block against nft's listing of the `$ruleset` built before
it. A block that starts with `// Throws SomeException` must throw it.
