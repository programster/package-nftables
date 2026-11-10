# Named sets

- [Creating a set](#creating-a-set)
- [Matching against a set](#matching-against-a-set)
- [Other types of set](#other-types-of-set)
- [Sets that rules add to](#sets-that-rules-add-to)
- [Changing a set at runtime](#changing-a-set-at-runtime)

A named set is a set of values (e.g. addresses to block) that lives in a table, alongside its chains. Unlike an
[anonymous set](expressions.md#sets-ranges-and-prefixes), it can be shared by several rules, and its elements can be
changed without reloading the rules. The examples leave out `use` statements. Every class is in
`Programster\Nftables`, or one of its `Enums`, `Statements`, `Expressions` and `Exceptions` namespaces.

## Creating a set
The two most common kinds have their own creators, which always give the set the interval flag, so it can hold
networks and ranges as well as single values:

```php
$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);

$blocklist = NamedSet::createAddressSet($table, "blocklist", IpVersion::IPV4, "198.51.100.7", "203.0.113.0/24");
$adminPorts = NamedSet::createPortSet($table, "admin_ports", 22, new PortRange(8000, 8080));
```

An address set holds IPv4 or IPv6 addresses, not both, and every address is checked to be the right version (and a
network, if it's a CIDR).

## Matching against a set
`MatchFactory::createInSet()` matches part of a packet against a set, or with `MatchMode::DOES_NOT_MATCH`, checks that
it isn't in it. Adding a rule that uses a set adds the set to the ruleset too:

```php
$sourceAddress = PayloadExpression::create(PayloadField::IP_SADDR);
$destinationPort = PayloadExpression::create(PayloadField::TCP_DPORT);
$fromOffice = MatchFactory::createSourceAddress("198.51.100.0/24", MatchMode::DOES_NOT_MATCH);

$ruleset = new Ruleset();
$ruleset->addRule(Rule::create($input, MatchFactory::createInSet($sourceAddress, $blocklist), Verdict::DROP));
$ruleset->addRule(Rule::create($input, MatchFactory::createInSet($destinationPort, $adminPorts), $fromOffice, Verdict::DROP));
```

```nft
set blocklist {
	type ipv4_addr
	flags interval
	elements = { 198.51.100.7, 203.0.113.0/24 }
}

set admin_ports {
	type inet_service
	flags interval
	elements = { 22, 8000-8080 }
}

ip saddr @blocklist drop
tcp dport @admin_ports ip saddr != 198.51.100.0/24 drop
```

For a match built by hand, `$set->getReference()` gives the reference (`@blocklist`) to use as its value. A rule can
only use a set in its own table, so using one from another table throws an `UnsuitableChainException`.

## Other types of set
Any other set is created with `NamedSet::create()`, from its table, name, `SetType` and any `SetFlag`s. Then
`withElements()` gives a copy with its initial elements, and `withTimeout()` a copy whose elements expire after that
many seconds:

```php
$trusted = NamedSet::create($table, "trusted", SetType::IFNAME)->withElements("eth1", "wg0");
$recent = NamedSet::create($table, "recent", SetType::IPV4_ADDR)->withElements("10.0.0.9")->withTimeout(3600);
$addressAndPort = new SetTypeCollection([SetType::IPV4_ADDR, SetType::INET_SERVICE]);
$pairs = NamedSet::create($table, "pairs", $addressAndPort)->withElements(new ConcatExpression("10.0.0.1", 22));
$ruleset->addSet($trusted);
$ruleset->addSet($recent);
$ruleset->addSet($pairs);
```

```nft
type ifname
timeout 1h
type ipv4_addr . inet_service
elements = { 10.0.0.1 . 22 }
```

- A `SetTypeCollection` of several types makes a set of concatenations, e.g. address and port pairs, matched with a
  `ConcatExpression`. The collection rejects anything that isn't a `SetType` as it's built.
- `SetFlag::INTERVAL` is needed for a set holding ranges or prefixes. Adding one without it throws a
  `BadArgumentException`, rather than nft failing to load the ruleset later.
- `withTimeout()` adds `SetFlag::TIMEOUT` itself, as nft needs it for a timeout.
- `SetFlag::CONSTANT` stops the elements being changed once it's loaded.

## Sets that rules add to
A [SetUpdateStatement](statements.md#adding-to-sets-from-rules-meters) adds values from packets to a set as they
arrive, e.g. the addresses that knock on a port, or that send too many new connections (a meter). As traffic decides
what goes in it, the set needs a size, with `withSize()`, so it can't be made to fill memory, and a timeout, so old
elements make room for new ones:

```php
$recentlySeen = NamedSet::create($table, "recently_seen", SetType::IPV4_ADDR)->withTimeout(300)->withSize(10000);
$ruleset->addSet($recentlySeen);
```

```nft
size 10000
timeout 5m
```

## Changing a set at runtime
A named set's elements can be changed while it's loaded, without touching the rules, e.g. to block an address straight
away:

```bash
nft add element inet firewall blocklist '{ 192.0.2.66 }'
```

Reloading the ruleset recreates its sets with only the elements given in PHP, so elements added at runtime are lost.
Anything that needs to survive a reload has to go in the ruleset too.
