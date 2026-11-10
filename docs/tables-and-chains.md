# Tables and chains

- [Tables](#tables)
- [Base chains](#base-chains)
  - [Types and hooks](#types-and-hooks)
  - [Priorities](#priorities)
  - [Devices](#devices)
- [Regular chains](#regular-chains)

The examples leave out `use` statements. Every class is in `Programster\Nftables`, or one of its `Enums`,
`Statements`, `Expressions` and `Exceptions` namespaces.

## Tables
A table holds chains and [sets](sets.md), and belongs to one address family, which decides which packets its chains
see:

| `Family` | Sees |
|---|---|
| `IP` | IPv4 packets |
| `IP6` | IPv6 packets |
| `INET` | Both IPv4 and IPv6, so one set of rules can cover both |
| `ARP` | ARP packets |
| `BRIDGE` | Packets passing through a bridge |
| `NETDEV` | Packets as they arrive at, or leave, a specific network device |

```php
$table = new Table("firewall", Family::INET);
```

Pick a distinctive name, not e.g. `filter` or `nat`, so it can't clash with a table that other software uses (see
[reset modes](rulesets.md#reset-modes)).

A table can be given `TableFlag::DORMANT`, which keeps it and its chains loaded but turns off all of its rules. It
needs nft 1.1.3 (or Rocky/AlmaLinux/RHEL 9): older nft silently drops the flag, so the ruleset's
[target](targets.md) has to be new enough. nft's
`owner` and `persist` flags aren't offered: they tie a table to the process that created it, and nft exits as soon as
it has loaded a file, so an owned table (and the firewall in it) would be deleted straight away.

## Base chains
A base chain is attached to a hook in the network stack, and sees every packet that passes that point:

```php
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
```

Its policy decides what happens to a packet that gets to the end of the chain without a rule deciding on it:
`Policy::ACCEPT` or `Policy::DROP`. There's no default, so a chain never drops (or accepts) everything without that
being chosen.

### Types and hooks
| `ChainType` | For | Families | Hooks |
|---|---|---|---|
| `FILTER` | Accepting, dropping and other filtering | All | All of the family's |
| `NAT` | Network address translation. Only sees the first packet of each connection. | `IP`, `IP6`, `INET` | `PREROUTING`, `INPUT`, `OUTPUT`, `POSTROUTING` |
| `ROUTE` | Rerouting packets whose marks or addresses change | `IP`, `IP6`, `INET` | `OUTPUT` |

| `ChainHook` | Sees | Families |
|---|---|---|
| `PREROUTING` | Every incoming packet, before routing decides where it's going | `IP`, `IP6`, `INET`, `BRIDGE` |
| `INPUT` | Incoming packets addressed to this machine | All but `NETDEV` |
| `FORWARD` | Packets passing through this machine, to somewhere else | `IP`, `IP6`, `INET`, `BRIDGE` |
| `OUTPUT` | Packets sent by processes on this machine | All but `NETDEV` |
| `POSTROUTING` | Every outgoing packet, after routing, just before it leaves | `IP`, `IP6`, `INET`, `BRIDGE` |
| `INGRESS` | Packets as they arrive at a device | `NETDEV`, `INET` |
| `EGRESS` | Packets as they leave a device | `NETDEV` |

A combination that can't work (e.g. a NAT chain on the forward hook, or a prerouting chain in an ARP table) throws a
`BadArgumentException` when the chain is created.

### Priorities
Chains on the same hook run in order of priority, lowest first. A priority is either one of nft's named priorities,
or any integer:

| `Priority` | Value | For |
|---|---|---|
| `RAW` | -300 | Before connection tracking, e.g. for `NotrackStatement` |
| `MANGLE` | -150 | Changing packets |
| `DSTNAT` | -100 | Destination NAT |
| `FILTER` | 0 | Filtering |
| `SECURITY` | 50 | Security modules (SELinux) |
| `SRCNAT` | 100 | Source NAT |

The bridge family has its own values (`DSTNAT` -300, `FILTER` -200, `OUT` 100 and `SRCNAT` 300), and the ARP and
netdev families only have `FILTER`. To run a chain just before or after one of them, give an integer relative to it:

```php
$priority = Priority::FILTER->getValue(Family::INET) - 10;
$early = new BaseChain("early", $table, ChainType::FILTER, ChainHook::INPUT, $priority, Policy::ACCEPT);

$ruleset = new Ruleset();
$ruleset->addChain($early);
```

```nft
type filter hook input priority filter - 10; policy accept;
```

Named priorities are always sent to nft as their number. nft's JSON parser quietly ignores a priority given as a
name, and creates a chain with no hook, which sees no packets.

### Devices
Chains on the ingress and egress hooks belong to one network device, which is required for them, and not allowed for
any other hook. They need nft 1.0.6 or later, and egress also needs kernel 5.16, so the ruleset's
[target](targets.md) has to have those:

```php
$netdev = new Table("edge", Family::NETDEV);
$ingress = new BaseChain("ingress", $netdev, ChainType::FILTER, ChainHook::INGRESS, Priority::FILTER, Policy::ACCEPT, "lo");

// Ingress and egress chains need nft 1.0.6 or later, so the ruleset needs a target that has it.
$ruleset = new Ruleset(NftablesTarget::DEBIAN_12);
$ruleset->addChain($ingress);
```

```nft
type filter hook ingress device "lo" priority filter; policy accept;
```

## Regular chains
A regular chain isn't attached to a hook, so it only sees the packets that a rule sends it with a `JumpStatement` or
`GotoStatement`. It's a way of grouping rules, e.g. all the rules for one service, so they can be shared:

```php
$ssh = new RegularChain("ssh", $table);
$isSsh = MatchFactory::createDestinationPorts(Protocol::TCP, 22);

$ruleset = new Ruleset();
$ruleset->addRule(Rule::create($input, $isSsh, new JumpStatement($ssh)));
$ruleset->addRule(Rule::create($ssh, MatchFactory::createSourceAddress("198.51.100.0/24"), Verdict::ACCEPT));
$ruleset->addRule(Rule::create($ssh, new LogStatement("ssh refused: "), Verdict::DROP));
```

```nft
chain input {
	type filter hook input priority filter; policy drop;
	tcp dport 22 jump ssh
}

chain ssh {
	ip saddr 198.51.100.0/24 accept
	log prefix "ssh refused: " drop
}
```

- After a jump, when the regular chain ends (or a rule in it returns with `Verdict::RETURN`), evaluation carries on
  with the rule after the jump.
- A `GotoStatement` doesn't come back: when the regular chain ends, evaluation carries on as if the chain that went to
  it had ended too.

A rule can only jump to a chain in its own table, so jumping to one in another table throws an
`UnsuitableChainException`.
