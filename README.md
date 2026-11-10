Nftables Package
================

[![Tests](https://github.com/programster/package-nftables/actions/workflows/tests.yml/badge.svg)](https://github.com/programster/package-nftables/actions/workflows/tests.yml)

A PHP package for generating nftables rulesets as JSON, for loading with `nft --json --file`. It's built to make the
safe thing the easy thing:

* **Reloading is atomic.** A ruleset clears out its old rules inside the same file, so a load that fails changes
  nothing, and reloading never stacks up duplicate rules. Tables owned by other software (fail2ban, Docker) are left
  alone by default.
* **Mistakes are caught in PHP**, with a message that says what's wrong, rather than later in nft: a port above 65535,
  a host CIDR where nft needs a network, a NAT rule in a filter chain, a jump to another table, and so on.
* **Risky choices are explicit.** Flushing every table on the machine, a chain's policy, what happens to queued
  packets when nothing's listening, and which packets a rate limit or quota matches all have to be chosen, rather than
  defaulting to something surprising. A set that rules add to must have a size, so traffic can't fill memory.
* **It knows where the rules will be loaded.** Tell it the server's OS (e.g. Debian 11, Ubuntu 22.04 or Rocky Linux 8)
  or nft version, and it refuses anything that server's nft can't load, or would silently ignore. Without one, it
  assumes the oldest supported, so the rules load anywhere. See [targets](docs/targets.md).
* **It's tested against real nft**: the nft of every supported OS, from 0.9.8 (Debian 11) to 1.1.6 (Ubuntu 26.04), and
  PHP 8.2 to 8.5, including every example in the docs.

## Installing
Version 1.0 is in alpha, so ask for it explicitly:

```bash
composer require programster/nftables:^1.0@alpha
```

Upgrading from 0.x? See [upgrading](docs/upgrading.md): nearly everything has been renamed, and a few things behave
differently.

## Example
```php
use Programster\Nftables\BaseChain;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\PortSet;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);

$ruleset = new Ruleset();
$ruleset->addRule(RuleFactory::createAcceptInterface($input, "lo"));
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", new PortSet(80, 443)));
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", 22, sourceAddress: "198.51.100.0/24"));

file_put_contents("/etc/firewall/ruleset.json", $ruleset->toJson());
```

```bash
nft --json --file /etc/firewall/ruleset.json
```

```nft
table inet firewall {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "eth0" tcp dport { 80, 443 } accept
		iifname "eth0" tcp dport 22 ip saddr 198.51.100.0/24 accept
	}
}
```

Load the file in one go like this, and **never** run `nft flush ruleset` as a separate command first: if the load then
failed, the machine would be left with no firewall at all. See [loading it safely](docs/rulesets.md#loading-it-safely).

## Documentation
* [Getting started](docs/getting-started.md): installing, a complete firewall and NAT gateway, and how it fits
  together
* [Rulesets](docs/rulesets.md): reset modes, loading safely, and what gets added for you
* [Targets](docs/targets.md): telling it where the rules will be loaded, and the features that need a newer nft
* [Tables and chains](docs/tables-and-chains.md): families, base chains (types, hooks, priorities) and regular chains
* [Rules](docs/rules.md): rules, and the factories for common rules and matches
* [Statements](docs/statements.md): verdicts, matches, logging, rate limits, quotas, reject, NAT, marks, synproxy,
  transparent proxying, queueing, and adding to sets from rules (meters)
* [Expressions](docs/expressions.md): packet headers, metadata, sets, ranges, prefixes, ports, routing lookups,
  number generators, hashes, OS fingerprinting and SCTP chunks
* [Named sets](docs/sets.md): allowlists, blocklists and other sets
* [Maps and verdict maps](docs/maps.md): port forwarding and dispatching to chains with one lookup
* [Flowtables](docs/flowtables.md): a fast path for forwarded connections
* [Named objects](docs/objects.md): shared counters, quotas and limits, conntrack helpers and timeouts, synproxies and
  security marks
* [Errors](docs/errors.md): the exceptions, and when they're thrown
* [Upgrading from 0.x](docs/upgrading.md)
* [Testing](docs/testing.md): running the tests locally, on every PHP version and target, and in CI
