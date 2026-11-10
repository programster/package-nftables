# Expressions

- [Plain values](#plain-values)
- [Packet headers](#packet-headers)
- [Metadata and connection tracking](#metadata-and-connection-tracking)
- [Sets, ranges and prefixes](#sets-ranges-and-prefixes)
- [Ports and connection states](#ports-and-connection-states)
- [Existence checks](#existence-checks)
- [Routing lookups (fib and rt)](#routing-lookups-fib-and-rt)
- [IPv6 extension headers and TCP options](#ipv6-extension-headers-and-tcp-options)
- [Combining values](#combining-values)
- [Map lookups](#map-lookups)
- [Number generators and hashes](#number-generators-and-hashes)
- [Operating system fingerprinting](#operating-system-fingerprinting)
- [SCTP chunks](#sctp-chunks)
- [Anything else](#anything-else)

Expressions are the values inside statements: what a match reads from the packet, and what it compares it with. They
implement the `Expression` interface. The examples match against them in this chain, and leave out `use` statements.
Every class is in `Programster\Nftables`, or one of its `Enums`, `Statements`, `Expressions` and `Exceptions`
namespaces.

```php
$table = new Table("t", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);
$ruleset = new Ruleset();
```

## Plain values
Wherever a statement takes an expression as a value, a plain string or integer works too, e.g. `22`, `"eth0"` or
`"10.0.0.1"`. The one exception is a string starting with `@`, which nft would read as a reference to a set, so it
throws a `BadArgumentException` rather than letting a value become one by accident. Use a
[set reference](sets.md#matching-against-a-set) for that.

## Packet headers
A `PayloadExpression` reads a field from the packet's headers. `PayloadField` lists nft's named fields, written as the
protocol, then the field, e.g. `PayloadField::TCP_DPORT` for `tcp dport`, or `PayloadField::IP6_SADDR` for
`ip6 saddr`. `TH_SPORT` and `TH_DPORT` are the ports of whichever transport protocol the packet has.

```php
$type = PayloadExpression::create(PayloadField::ICMP_TYPE);
$ruleset->addRule(Rule::create($input, new MatchStatement($type, Operator::EQUALS, "echo-request"), Verdict::ACCEPT));
```

```nft
icmp type echo-request accept
```

For a header nft doesn't name, `PayloadExpression::createRaw()` reads any run of bits, from the link, network or
transport layer header.

## Metadata and connection tracking
A `MetaExpression` reads metadata about the packet, rather than its contents: `MetaKey::IIFNAME` (the interface it
arrived on), `OIFNAME`, `MARK`, `L4PROTO` (its transport protocol), `SKUID` (the user that sent it), `TIME`, and so on.

A `CtExpression` reads connection tracking data about its connection: `CtKey::STATE`, `MARK`, `HELPER`, and so on.
The keys that differ between the two directions of a connection (e.g. `SADDR`) also take a `CtDirection`, and the
address ones an `IpVersion`. In an `inet` table, nft also needs to know the packet's IP version before an address
key, so match `MetaKey::NFPROTO` first, as below. (nft treats that match as implied, and leaves it out of
`nft list ruleset`.)

```php
$ownMark = new BinaryOperationExpression(BinaryOperator::AND, new MetaExpression(MetaKey::MARK), 0xFF);
$startedBy = new CtExpression(CtKey::SADDR, CtDirection::ORIGINAL, IpVersion::IPV4);
$ruleset->addRule(Rule::create($input, new MatchStatement($ownMark, Operator::EQUALS, 1), Verdict::ACCEPT));
$isIpv4 = new MatchStatement(new MetaExpression(MetaKey::NFPROTO), Operator::EQUALS, "ipv4");
$ruleset->addRule(Rule::create($input, $isIpv4, new MatchStatement($startedBy, Operator::EQUALS, "10.0.0.1"), Verdict::ACCEPT));
```

```nft
meta mark & 0x000000ff == 0x00000001 accept
ct original ip saddr 10.0.0.1 accept
```

## Sets, ranges and prefixes
| Expression | Is | e.g. |
|---|---|---|
| `new SetExpression(22, 80)` | An anonymous set, written into the rule | `{ 22, 80 }` |
| `new RangeExpression(5000, 6000)` | A range, inclusive | `5000-6000` |
| `new PrefixExpression("10.0.0.0", 8)` | A network | `10.0.0.0/8` |
| `PrefixExpression::createFromCidr("fd00::/8")` | A network, from a CIDR | `fd00::/8` |

A prefix must be a network, with its host bits all zero, or it throws an `InvalidAddressException`. For a set that's
shared between rules, or changed without reloading, use a [named set](sets.md) instead.

## Ports and connection states
A `PortSet` (individual ports) and a `PortRange` are expressions too, and every port is checked to be between 1 and
65535. A `PortRange` needs its highest port above its lowest: for a single port, use the port on its own.

A `ConnectionStateSet` holds one or more `ConnectionState`s (`NEW`, `ESTABLISHED`, `RELATED`, `INVALID` and
`UNTRACKED`), for matching a connection in any of them. Duplicates in either are ignored.

## Existence checks
Some things are checked for being there, rather than compared with a value: an IPv6 extension header, a TCP option, an
[SCTP chunk](#sctp-chunks), or a route found by a fib lookup. `MatchFactory::createExistence()` takes one of those, and
`Existence::EXISTS` or `Existence::MISSING`:

```php
$fragmentHeader = ExthdrExpression::create(Ipv6ExtensionHeader::FRAGMENT);
$sackPermitted = TcpOptionExpression::create(TcpOption::SACK_PERMITTED);
$ruleset->addRule(Rule::create($input, MatchFactory::createExistence($fragmentHeader, Existence::EXISTS), Verdict::DROP));
$ruleset->addRule(Rule::create($input, MatchFactory::createExistence($sackPermitted, Existence::MISSING), Verdict::ACCEPT));
```

```nft
exthdr frag exists drop
tcp option sack-perm missing accept
```

Only a whole header, option or chunk can be checked for (not one of its fields), and only a fib lookup of an interface
(`FibResult::OIF` or `OIFNAME`, not `TYPE`). Anything else throws a `BadArgumentException`.

## Routing lookups (fib and rt)
A `FibExpression` looks up one of the packet's addresses in the routing table (`FibResult::OIF`, `OIFNAME` or
`TYPE`). Its `FibFlag`s say what to look up: exactly one of `SADDR` and `DADDR`, and optionally `IIF` or `OIF` (not
both) and `MARK`. Its most common use is spotting spoofed packets, which
[`RuleFactory::createReversePathFilter()`](rules.md#spotting-spoofed-packets) does. A `TYPE` lookup is compared with
an `AddressType`:

```php
$isForThisMachine = new MatchStatement(new FibExpression(FibResult::TYPE, FibFlag::DADDR), Operator::EQUALS, AddressType::LOCAL);
$ruleset->addRule(Rule::create($input, $isForThisMachine, Verdict::ACCEPT));
```

```nft
fib daddr type local accept
```

An `RtExpression` reads routing data about the packet: its route's MTU (`RtKey::MTU`), its next hop (`NEXTHOP`) or
its routing realm (`CLASSID`). See [MSS clamping](rules.md#mss-clamping) for its most common use.

## IPv6 extension headers and TCP options
An `ExthdrExpression` is an IPv6 extension header, and a `TcpOptionExpression` a TCP option. `create()` gives the
whole header or option, for an [existence check](#existence-checks), and `createField()` one of its fields, to match
on or change (with a `MangleStatement`):

```php
$moreFragments = ExthdrExpression::createField(Ipv6ExtensionHeaderField::FRAG_MORE_FRAGMENTS);
$segmentSize = TcpOptionExpression::createField(TcpOptionField::MAXSEG_SIZE);
$ruleset->addRule(Rule::create($input, new MatchStatement($moreFragments, Operator::EQUALS, 1), Verdict::DROP));
$ruleset->addRule(Rule::create($input, new MatchStatement($segmentSize, Operator::LESS_THAN, 536), Verdict::DROP));
```

```nft
frag more-fragments 1 drop
tcp option maxseg size < 536 drop
```

The headers are `Ipv6ExtensionHeader::HOP_BY_HOP`, `ROUTING`, `FRAGMENT`, `DESTINATION_OPTIONS` and `MOBILITY`. The
options are `TcpOption::MAXSEG` (the maximum segment size), `WINDOW` (window scaling), `SACK_PERMITTED`, `SACK` and
`TIMESTAMP`. A selective acknowledgement's blocks are fields of `SACK` (`TcpOptionField::SACK_LEFT` for the first,
then `SACK1_LEFT` to `SACK3_RIGHT`).

## Combining values
A `ConcatExpression` joins values, so they're matched together, e.g. an address and a port against a set of pairs:

```php
$addressAndPort = new ConcatExpression(PayloadExpression::create(PayloadField::IP_SADDR), PayloadExpression::create(PayloadField::TCP_DPORT));
$allowed = new SetExpression(new ConcatExpression("10.0.0.1", 22), new ConcatExpression("10.0.0.2", 443));
$ruleset->addRule(Rule::create($input, new MatchStatement($addressAndPort, Operator::EQUALS, $allowed), Verdict::ACCEPT));
```

```nft
ip saddr . tcp dport { 10.0.0.1 . 22, 10.0.0.2 . 443 } accept
```

A `BinaryOperationExpression` applies a bitwise operation (`BinaryOperator::AND`, `OR`, `XOR`, `SHIFT_LEFT` or
`SHIFT_RIGHT`), e.g. to check only some bits of a mark, as above.

## Map lookups
A `MapLookupExpression` looks a key up in a map, and stands for the value it maps to, e.g. the address to port forward
to. Get one from `NamedMap::lookUp()` or `AnonymousMap::lookUp()`. See [maps](maps.md).

## Number generators and hashes
A `NumgenExpression` gives each packet a number, counting up in turn (`NumgenMode::INCREMENTAL`) or at random
(`RANDOM`), from an offset (0 by default) up to the offset plus its modulus, less one. A `HashExpression` gives a
number from a hash of the packet instead, so packets with the same values always get the same number:
`createJhash()` hashes any values, and `createSymhash()` the addresses and ports, the same way in both directions.

```php
$mark = new MetaExpression(MetaKey::MARK);
$byClient = HashExpression::createJhash(PayloadExpression::create(PayloadField::IP_SADDR), 2, 0, 0x2a);
$ruleset->addRule(Rule::create($input, new MangleStatement($mark, new NumgenExpression(NumgenMode::RANDOM, 4))));
$ruleset->addRule(Rule::create($input, new MangleStatement($mark, $byClient)));
```

```nft
meta mark set numgen random mod 4
meta mark set jhash ip saddr mod 2 seed 0x2a
```

They're most often looked up in a map, to spread connections over several machines: taking turns, or with a hash, so
each client always goes to the same one. See [anonymous maps](maps.md#anonymous-maps). A jhash without a seed gets a
random one each time the ruleset loads, so a client can go to a different machine after a reload.

## Operating system fingerprinting
An `OsfExpression` is the operating system a TCP SYN packet looks like it came from, guessed from how its TCP options
are laid out (`OsfKey::NAME`, e.g. `Linux`, or `VERSION`, e.g. `Linux:4.20`):

```php
$looksLikeLinux = new MatchStatement(new OsfExpression(OsfKey::NAME, OsfTtlCheck::LOOSE), Operator::EQUALS, "Linux");
$ruleset->addRule(Rule::create($input, $looksLikeLinux, new LogStatement("linux: ")));
```

```nft
osf ttl loose name "Linux" log prefix "linux: "
```

- The kernel only knows the fingerprints that have been loaded into it (e.g. with `nfnl_osf` and the `pf.os` file
  from the iptables package). Without them, every packet is `unknown`.
- `OsfTtlCheck::EXACT` (the default) only matches machines on the same network, as each router a packet passes lowers
  its TTL. `LOOSE` allows for that, and `SKIP` ignores the TTL.
- A client can fake its fingerprint, so this suits logging and statistics better than security.
- It needs kernel 4.19, so isn't available on RHEL 8.

## SCTP chunks
An `SctpChunkExpression` is a chunk of an SCTP packet. As for TCP options, `create()` gives the whole chunk (an
`SctpChunk`), for an [existence check](#existence-checks), and `createField()` one of its fields (an
`SctpChunkField`), which throws a `BadArgumentException` if that chunk doesn't have the field. They need nft 1.0.2
and kernel 5.14 (or RHEL 8's, which has them backported):

```php
$ruleset = new Ruleset(NftablesTarget::UBUNTU_22_04);
$hasInit = MatchFactory::createExistence(SctpChunkExpression::create(SctpChunk::INIT), Existence::EXISTS);
$sequenceNumber = SctpChunkExpression::createField(SctpChunk::DATA, SctpChunkField::TSN);
$ruleset->addRule(Rule::create($input, $hasInit, Verdict::ACCEPT));
$ruleset->addRule(Rule::create($input, new MatchStatement($sequenceNumber, Operator::EQUALS, 0), Verdict::DROP));
```

```nft
sctp chunk init exists accept
sctp chunk data tsn 0 drop
```

## Anything else
For an expression this package doesn't model yet (e.g. a `socket` expression), a `RawExpression` takes it in nft's JSON
form, exactly as the [libnftables-json
documentation](https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html) describes it. It's passed on
without any checks.

```php
$hasTransparentSocket = new RawExpression(["socket" => ["key" => "transparent"]]);
$ruleset->addRule(Rule::create($input, new MatchStatement($hasTransparentSocket, Operator::EQUALS, 1), Verdict::ACCEPT));
```

```nft
socket transparent 1 accept
```
