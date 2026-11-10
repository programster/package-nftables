Nftables Package
================

[![Tests](https://github.com/programster/package-nftables/actions/workflows/tests.yml/badge.svg)](https://github.com/programster/package-nftables/actions/workflows/tests.yml)

## Documentation
* [Examples](docs/examples.md): complete rulesets for a NAT gateway with port forwards (IPv4 and IPv6), the same
  with its forwards in maps, and a web server
* [Getting started](docs/getting-started.md): installing, a complete firewall and NAT gateway, and how it fits
  together
* [Rulesets](docs/rulesets.md): reset modes, loading safely, and what gets added for you
* [Targets](docs/targets.md): telling it where the rules will be loaded, and the features that need a newer nft
* [Tables and chains](docs/tables-and-chains.md): families, base chains (types, hooks, priorities) and regular chains
* [Rules](docs/rules.md): rules, and the factories for common rules and matches
* [Statements](docs/statements.md): verdicts, matches, logging, rate limits, quotas, connection limits, reject, NAT,
  marks, synproxy, transparent proxying, queueing, adding to sets from rules (meters), and copying and forwarding
  packets
* [Expressions](docs/expressions.md): packet headers, metadata, sets, ranges, prefixes, ports, routing lookups,
  sockets, IPsec, number generators, hashes, OS fingerprinting and SCTP chunks
* [Named sets](docs/sets.md): allowlists, blocklists and other sets
* [Maps and verdict maps](docs/maps.md): port forwarding and dispatching to chains with one lookup
* [Flowtables](docs/flowtables.md): a fast path for forwarded connections
* [Named objects](docs/objects.md): shared counters, quotas and limits, conntrack helpers, timeouts and expectations,
  synproxies and security marks
* [Errors](docs/errors.md): the exceptions, and when they're thrown
* [Upgrading from 0.x](docs/upgrading.md)
* [Testing](docs/testing.md): running the tests locally, on every PHP version and target, and in CI

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
A NAT gateway (e.g. a VM in Proxmox) with two network interfaces: `eth0` on the internet, with the one public IPv4
address, and `eth1` on a LAN of guests. The guests reach the internet through it, NATed behind its address. The internet
reaches the web proxy's HTTP, HTTPS and HTTP/3 (UDP 443) through port forwards, and your trusted address can SSH to the
gateway, and to each guest on a port of its own:

```php
use Programster\Nftables\BaseChain;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

$loopback = "lo";
$wan = "eth0";
$lan = "eth1";
$trustedIp = "198.51.100.7";
$webProxy = "10.0.0.10";
$appServer = "10.0.0.11";
$database = "10.0.0.12";

$table = new Table("gateway", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::DROP);
$prerouting = new BaseChain("prerouting", $table, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
$postrouting = new BaseChain("postrouting", $table, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT, Policy::ACCEPT);
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);

$ruleset = new Ruleset();

$ruleset->addRule(
    // The gateway itself: the LAN can reach it, and your trusted address can SSH to it.
    RuleFactory::createAcceptInterface($input, $loopback),
    RuleFactory::createAcceptInterface($input, $lan),
    RuleFactory::createAcceptInterface($input, $wan, $replies),
    RuleFactory::createAcceptPort($input, $wan, 22, sourceAddress: $trustedIp, comment: "SSH to the gateway"),

    // The guests reach the internet through it, NATed behind its address.
    RuleFactory::createForward($forward, $lan, $wan),
    RuleFactory::createForward($forward, $wan, $lan, $replies),
    RuleFactory::createMasquerade($postrouting, $wan),

    // Web proxy - HTTP, HTTPS and HTTP/3 port forwarding from anywhere, and SSH from the trusted address on port 2210.
    RuleFactory::createPortForward($prerouting, $wan, 80, $webProxy, comment: "HTTP"),
    RuleFactory::createPortForward($prerouting, $wan, 443, $webProxy, comment: "HTTPS"),
    RuleFactory::createPortForward($prerouting, $wan, 443, $webProxy, protocol: Protocol::UDP, comment: "HTTP/3"),
    RuleFactory::createPortForward($prerouting, $wan, 2210, $webProxy, 22, sourceAddress: $trustedIp, comment: "SSH to the web proxy"),

    // App server - SSH port forwarding from the trusted address on port 2211.
    RuleFactory::createPortForward($prerouting, $wan, 2211, $appServer, 22, sourceAddress: $trustedIp, comment: "SSH to the app server"),

    // Database - SSH port forwarding from the trusted address on port 2212.
    RuleFactory::createPortForward($prerouting, $wan, 2212, $database, 22, sourceAddress: $trustedIp, comment: "SSH to the database"),

    // Let the port forwarded connections through the forward chain.
    RuleFactory::createAcceptPortForwards($forward),
);

file_put_contents("/etc/gateway/ruleset.json", $ruleset->toJson());
```

Load it with `nft --json --file /etc/gateway/ruleset.json`, and `nft list ruleset` shows:

```nft
table inet gateway {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "eth1" accept
		iifname "eth0" ct state established,related accept
		iifname "eth0" tcp dport 22 ip saddr 198.51.100.7 accept comment "SSH to the gateway"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "eth1" oifname "eth0" accept
		iifname "eth0" oifname "eth1" ct state established,related accept
		ct status dnat accept
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" tcp dport 80 dnat ip to 10.0.0.10 comment "HTTP"
		iifname "eth0" tcp dport 443 dnat ip to 10.0.0.10 comment "HTTPS"
		iifname "eth0" udp dport 443 dnat ip to 10.0.0.10 comment "HTTP/3"
		iifname "eth0" tcp dport 2210 ip saddr 198.51.100.7 dnat ip to 10.0.0.10:22 comment "SSH to the web proxy"
		iifname "eth0" tcp dport 2211 ip saddr 198.51.100.7 dnat ip to 10.0.0.11:22 comment "SSH to the app server"
		iifname "eth0" tcp dport 2212 ip saddr 198.51.100.7 dnat ip to 10.0.0.12:22 comment "SSH to the database"
	}
}
```

Load the file in one go like this, and **never** run `nft flush ruleset` as a separate command first: if the load then
failed, the machine would be left with no firewall at all. See [loading it safely](docs/rulesets.md#loading-it-safely).

### Taking it further: adding IPv6
With IPv6, each guest can have a public address of its own, from a network routed to the gateway. The gateway then
routes their IPv6 traffic rather than NATing it, so this masquerades IPv4 only, accepts the
[ICMPv6 that IPv6 needs](docs/rules.md#accepting-essential-icmpv6), and accepts the web proxy's HTTP, HTTPS and
HTTP/3, and SSH from the trusted address, at the guests' own addresses:

```php
use Programster\Nftables\BaseChain;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\PortSet;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

$loopback = "lo";
$wan = "eth0";
$lan = "eth1";
$trustedIp = "198.51.100.7";
$trustedIpv6Network = "2001:db8:ffff::/48";
$webProxy = "10.0.0.10";
$webProxyIpv6 = "2001:db8:0:1::10";
$appServer = "10.0.0.11";
$appServerIpv6 = "2001:db8:0:1::11";
$database = "10.0.0.12";
$databaseIpv6 = "2001:db8:0:1::12";

$table = new Table("gateway", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::DROP);
$prerouting = new BaseChain("prerouting", $table, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
$postrouting = new BaseChain("postrouting", $table, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT, Policy::ACCEPT);
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);

$ruleset = new Ruleset();

$ruleset->addRule(
    // The gateway itself: the LAN can reach it, and your trusted address can SSH to it.
    RuleFactory::createAcceptInterface($input, $loopback),
    RuleFactory::createAcceptInterface($input, $lan),
    RuleFactory::createAcceptInterface($input, $wan, $replies),
    RuleFactory::createAcceptEssentialIcmpv6($input),
    RuleFactory::createAcceptPort($input, $wan, 22, sourceAddress: $trustedIp, comment: "SSH to the gateway"),
    RuleFactory::createAcceptPort($input, $wan, 22, sourceAddress: $trustedIpv6Network, comment: "SSH to the gateway"),

    // The guests reach the internet through it: NATed for IPv4, and routed with their own addresses for IPv6.
    RuleFactory::createForward($forward, $lan, $wan),
    RuleFactory::createForward($forward, $wan, $lan, $replies),
    RuleFactory::createAcceptEssentialIcmpv6($forward),
    RuleFactory::createMasquerade($postrouting, $wan, IpVersion::IPV4),

    // Web proxy - HTTP, HTTPS and HTTP/3 from anywhere, and SSH from the trusted address. Port forwarded for IPv4 (SSH on port
    // 2210), and accepted at its own address for IPv6.
    RuleFactory::createPortForward($prerouting, $wan, 80, $webProxy, comment: "HTTP"),
    RuleFactory::createPortForward($prerouting, $wan, 443, $webProxy, comment: "HTTPS"),
    RuleFactory::createPortForward($prerouting, $wan, 443, $webProxy, protocol: Protocol::UDP, comment: "HTTP/3"),
    RuleFactory::createPortForward($prerouting, $wan, 2210, $webProxy, 22, sourceAddress: $trustedIp, comment: "SSH to the web proxy"),
    RuleFactory::createForward($forward, $wan, $lan, destinationPorts: new PortSet(80, 443), destinationAddress: $webProxyIpv6),
    RuleFactory::createForward($forward, $wan, $lan, protocol: Protocol::UDP, destinationPorts: 443, destinationAddress: $webProxyIpv6),
    RuleFactory::createForward($forward, $wan, $lan, destinationPorts: 22, sourceAddress: $trustedIpv6Network, destinationAddress: $webProxyIpv6),

    // App server - SSH from the trusted address. Port forwarded on port 2211 for IPv4, and accepted at its own address for IPv6.
    RuleFactory::createPortForward($prerouting, $wan, 2211, $appServer, 22, sourceAddress: $trustedIp, comment: "SSH to the app server"),
    RuleFactory::createForward($forward, $wan, $lan, destinationPorts: 22, sourceAddress: $trustedIpv6Network, destinationAddress: $appServerIpv6),

    // Database - SSH from the trusted address. Port forwarded on port 2212 for IPv4, and accepted at its own address for IPv6.
    RuleFactory::createPortForward($prerouting, $wan, 2212, $database, 22, sourceAddress: $trustedIp, comment: "SSH to the database"),
    RuleFactory::createForward($forward, $wan, $lan, destinationPorts: 22, sourceAddress: $trustedIpv6Network, destinationAddress: $databaseIpv6),

    // Let the port forwarded connections through the forward chain.
    RuleFactory::createAcceptPortForwards($forward),
);

file_put_contents("/etc/gateway/ruleset.json", $ruleset->toJson());
```

The [examples](docs/examples.md) show nft's listing of this, explain what each version lets through and how to set up
the gateway (forwarding, and the guests' IPv6 network), and have the same gateway with its forwards in maps, and a web
server.
