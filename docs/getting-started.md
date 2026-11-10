# Getting started

- [Installing](#installing)
- [A complete example](#a-complete-example)
- [Loading it](#loading-it)
- [How it fits together](#how-it-fits-together)

## Installing
Version 1.0 is in alpha, so ask for it explicitly. Composer won't install an alpha otherwise:

```bash
composer require programster/nftables:^1.0@alpha
```

It needs PHP 8.2 or above. The rulesets it generates can be loaded on a different machine, with nft 0.9.8 or above
(e.g. Debian 11, Ubuntu 22.04 or Rocky Linux 8, and anything newer).

## A complete example
A gateway with a WAN interface (`eth0`) and a LAN (`eth1`). It drops anything it doesn't expect, allows SSH from one
office network, lets the LAN out to the internet, and forwards port 443 to a web server on the LAN:

```php
use Programster\Nftables\BaseChain;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

$table = new Table("gateway", Family::IP);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::DROP);
$prerouting = new BaseChain("prerouting", $table, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
$postrouting = new BaseChain("postrouting", $table, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT, Policy::ACCEPT);
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);

$ruleset = new Ruleset();

$ruleset->addRule(
    RuleFactory::createAcceptInterface($input, "lo", comment: "loopback"),
    RuleFactory::createAcceptInterface($input, "eth1", comment: "the LAN"),
    RuleFactory::createAcceptInterface($input, "eth0", $replies, "replies to this machine's own connections"),
    RuleFactory::createAcceptPort($input, "eth0", 22, sourceAddress: "198.51.100.0/24", comment: "SSH from the office"),

    // The LAN can go out to the internet, and get replies back.
    RuleFactory::createForward($forward, "eth1", "eth0"),
    RuleFactory::createForward($forward, "eth0", "eth1", $replies),
    RuleFactory::createMasquerade($postrouting, "eth0"),

    // Port forward 443 to the web server, and let the forwarded traffic through.
    RuleFactory::createPortForward($prerouting, "eth0", 443, "10.0.0.10"),
    RuleFactory::createForward($forward, "eth0", "eth1", destinationPorts: 443, destinationAddress: "10.0.0.10"),
);

file_put_contents("/etc/gateway/ruleset.json", $ruleset->toJson());
```

## Loading it
Load the file with a single command, and check that it worked:

```bash
nft --json --file /etc/gateway/ruleset.json
```

`nft list ruleset` then shows what's loaded:

```nft
table ip gateway {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept comment "loopback"
		iifname "eth1" accept comment "the LAN"
		iifname "eth0" ct state established,related accept comment "replies to this machine's own connections"
		iifname "eth0" tcp dport 22 ip saddr 198.51.100.0/24 accept comment "SSH from the office"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "eth1" oifname "eth0" accept
		iifname "eth0" oifname "eth1" ct state established,related accept
		iifname "eth0" oifname "eth1" ip daddr 10.0.0.10 tcp dport 443 accept
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" tcp dport 443 dnat to 10.0.0.10
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}
}
```

nft applies the whole file as one transaction: if any part of it fails, nothing changes, and the rules that were
already loaded stay in place. That only protects you if the file is loaded in one go, so **never** run
`nft flush ruleset` as a separate command first. If the load then failed (e.g. because a PHP warning ended up in the
JSON), the machine would be left with no firewall at all. The ruleset already clears out its old rules itself, inside
the same transaction (see [Rulesets](rulesets.md#reset-modes)).

## How it fits together
- A [`Table`](tables-and-chains.md#tables) holds chains, and the [sets](sets.md), [maps](maps.md),
  [flowtables](flowtables.md) and [named objects](objects.md) its rules use. It belongs to an address family, such as
  `ip` (IPv4), `ip6` or `inet` (both).
- A [`BaseChain`](tables-and-chains.md#base-chains) is attached to a hook in the network stack (e.g. `input`, for
  packets addressed to this machine), and sees every packet that passes it. Its policy says what happens to packets
  that no rule decides on. A [`RegularChain`](tables-and-chains.md#regular-chains) only sees packets that are sent to
  it from another chain.
- A [`Rule`](rules.md) is a list of [statements](statements.md), applied to each packet in turn: usually some matches
  (e.g. "the destination port is 22"), then a verdict (e.g. accept). [`RuleFactory`](rules.md#rulefactory) creates the
  common ones.
- A [`Ruleset`](rulesets.md) puts it all together into a file nft can load, adding the tables, chains and everything
  else the rules need. Given the [target](targets.md) it will be loaded on, e.g.
  `new Ruleset(NftablesTarget::DEBIAN_12)`, it refuses anything that target's nft can't load. Without one, it assumes
  the oldest supported.
