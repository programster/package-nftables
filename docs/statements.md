# Statements

- [Verdicts](#verdicts)
- [Matches](#matches)
- [Counting and logging](#counting-and-logging)
- [Rate limits](#rate-limits)
- [Quotas](#quotas)
- [Rejecting](#rejecting)
- [Address translation (NAT)](#address-translation-nat)
- [Marks and other changes](#marks-and-other-changes)
- [Skipping connection tracking](#skipping-connection-tracking)
- [Synproxy](#synproxy)
- [Transparent proxying](#transparent-proxying)
- [Queueing to a program](#queueing-to-a-program)
- [Adding to sets from rules (meters)](#adding-to-sets-from-rules-meters)
- [Statements covered elsewhere](#statements-covered-elsewhere)
- [Anything else](#anything-else)

A rule is a list of statements, which all implement the `Statement` interface. The examples add them to rules in these
chains, and leave out `use` statements. Every class is in `Programster\Nftables`, or one of its `Enums`, `Statements`,
`Expressions` and `Exceptions` namespaces.

```php
$table = new Table("t", Family::IP);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);
$prerouting = new BaseChain("prerouting", $table, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
$postrouting = new BaseChain("postrouting", $table, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT, Policy::ACCEPT);
$isTcp = MatchFactory::createTransportProtocol(Protocol::TCP);
$ruleset = new Ruleset();
```

## Verdicts
A verdict decides what happens to the packet:

| Statement | Effect |
|---|---|
| `Verdict::ACCEPT` | Let it through this chain (later chains on the same hook still see it) |
| `Verdict::DROP` | Silently discard it. Nothing after this sees it. |
| `Verdict::CONTINUE` | Carry on with the next rule (what happens anyway at the end of a rule) |
| `Verdict::RETURN` | Go back to the chain that jumped here, or apply the policy in a base chain |
| `new JumpStatement($chain)` | Carry on in a [regular chain](tables-and-chains.md#regular-chains), then come back |
| `new GotoStatement($chain)` | Carry on in a regular chain, without coming back |

## Matches
A `MatchStatement` compares part of the packet (an [expression](expressions.md)) with a value. If they don't match,
the rest of the rule is skipped. [`MatchFactory`](rules.md#matchfactory) creates the common ones, and anything else
can be built from an expression, an `Operator` and a value:

```php
$dport = PayloadExpression::create(PayloadField::TCP_DPORT);
$ruleset->addRule(Rule::create($input, new MatchStatement($dport, Operator::LESS_THAN, 1024), Verdict::DROP));
```

```nft
tcp dport < 1024 drop
```

The operators are `EQUALS`, `NOT_EQUALS`, `LESS_THAN`, `GREATER_THAN`, `LESS_THAN_OR_EQUAL`, `GREATER_THAN_OR_EQUAL`,
and `IN`, which checks for any of a set of flags (e.g. connection states).

## Counting and logging
A `CounterStatement` counts the packets and bytes that reach it, as shown by `nft list ruleset`. A `LogStatement` logs
the packet to the kernel log, optionally with a prefix (up to 127 bytes), a level and extra details:

```php
$ruleset->addRule(Rule::create($input, new CounterStatement(), new LogStatement("dropped: ", LogLevel::INFO, LogFlag::TCP_SEQUENCE), Verdict::DROP));
```

```nft
counter packets 0 bytes 0 log prefix "dropped: " level info flags tcp sequence drop
```

## Rate limits
A `LimitStatement` matches packets depending on how fast they're arriving. Which packets it matches has to be chosen,
because it's easy to get backwards:

- `LimitMatch::OVER_LIMIT` matches the packets beyond the rate, e.g. to drop the excess.
- `LimitMatch::WITHIN_LIMIT` matches the packets up to the rate, e.g. to accept that many.

So matching `WITHIN_LIMIT` and then dropping would drop the allowed packets, and let the rest through. To allow at
most 10 new SSH connections a minute, with a burst of 5:

```php
$isNew = MatchFactory::createConnectionStates(new ConnectionStateSet(ConnectionState::NEW));
$isSsh = MatchFactory::createDestinationPorts(Protocol::TCP, 22);
$tooFast = new LimitStatement(10, LimitPeriod::MINUTE, LimitMatch::OVER_LIMIT, 5);
$ruleset->addRule(Rule::create($input, $isSsh, $isNew, $tooFast, Verdict::DROP));
```

```nft
tcp dport 22 ct state new limit rate over 10/minute burst 5 packets drop
```

The rate can also be in bytes, with `LimitUnit::BYTES`, `KBYTES` or `MBYTES`.

## Quotas
A `QuotaStatement` matches packets depending on how much traffic has reached it in total, e.g. to cut a machine off
once it has used its allowance. As with a rate limit, which packets it matches has to be chosen:

- `QuotaMatch::OVER_QUOTA` matches the packets once the quota is used up, e.g. to drop the rest.
- `QuotaMatch::WITHIN_QUOTA` matches the packets until it's used up, e.g. to accept that much.

So matching `WITHIN_QUOTA` and then dropping would drop the first part of the traffic, and let everything after it
through. To drop everything once 10 GB has arrived:

```php
$ruleset->addRule(Rule::create($input, new QuotaStatement(10240, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA), Verdict::DROP));
```

```nft
quota over 10240 mbytes drop
```

The amount is in `QuotaUnit::BYTES`, `KBYTES` or `MBYTES` (nft has no larger unit, and silently reads `gbytes` as
bytes). The count starts again whenever the ruleset is reloaded. A [NamedQuota](objects.md#counters-quotas-and-limits)
can be shared by several rules, and its usage read with `nft list quotas`.

## Rejecting
A `RejectStatement` drops the packet, but also tells the sender, so they fail straight away instead of waiting to time
out:

| Created with | Replies with | Tables |
|---|---|---|
| `RejectStatement::create()` | nft's default: ICMP port unreachable | All |
| `RejectStatement::createTcpReset()` | A TCP reset, as a closed port does. TCP packets only. | All |
| `RejectStatement::createIcmp(IcmpRejectCode)` | An ICMP error, for IPv4 | `ip`, `inet` |
| `RejectStatement::createIcmpv6(Icmpv6RejectCode)` | An ICMPv6 error, for IPv6 | `ip6`, `inet` |
| `RejectStatement::createIcmpx(IcmpxRejectCode)` | An ICMP error worded the same for IPv4 and IPv6 | `inet` |

```php
$ruleset->addRule(Rule::create($input, $isTcp, RejectStatement::createTcpReset()));
$ruleset->addRule(Rule::create($input, RejectStatement::createIcmp(IcmpRejectCode::ADMIN_PROHIBITED)));
```

```nft
reject with tcp reset
reject with icmp admin-prohibited
```

## Address translation (NAT)
These change a packet's addresses or ports. They belong in a `ChainType::NAT` chain, and only see the first packet of
each connection: the rest of the connection is translated the same way automatically.

| Statement | Changes | Chain |
|---|---|---|
| `DnatStatement::create($address, $port)` | The destination, e.g. to forward a port to another machine | prerouting (or output) |
| `SnatStatement::create($address, $port)` | The source, to a fixed address | postrouting (or input) |
| `new MasqueradeStatement($port)` | The source, to the address of the interface it leaves by | postrouting |
| `new RedirectStatement($port)` | The destination, to this machine, e.g. a local proxy | prerouting (or output) |

The port is optional, and can be a `PortRange` to pick one from. Changing the port needs a match on the transport
protocol earlier in the rule (e.g. a port match), as nft can't know there's a port otherwise. IPv6 addresses work too,
and in an `inet` table the IP version is worked out from the address. `NatFlag`s change how ports are picked.

`DnatStatement::createFromMap()` and `SnatStatement::createFromMap()` take the address (and port) from a map instead,
e.g. to do all of a gateway's port forwards in one rule. See [port forwarding with a
map](maps.md#port-forwarding-with-a-map).

```php
$ruleset->addRule(Rule::create($prerouting, $isTcp, DnatStatement::create("10.0.0.10", 8080)));
$ruleset->addRule(Rule::create($prerouting, $isTcp, new RedirectStatement(3128)));
$ruleset->addRule(Rule::create($postrouting, SnatStatement::create("203.0.113.1")));
$ruleset->addRule(Rule::create($postrouting, $isTcp, new MasqueradeStatement(new PortRange(1024, 65535), NatFlag::FULLY_RANDOM)));
```

```nft
meta l4proto tcp dnat to 10.0.0.10:8080
meta l4proto tcp redirect to :3128
snat to 203.0.113.1
meta l4proto tcp masquerade to :1024-65535 fully-random
```

## Marks and other changes
A `MangleStatement` changes part of a packet or its metadata. Its creators set the two marks, which later rules (or
routing, with `ip rule`) can act on:

- `MangleStatement::createSetMetaMark($mark)` marks the packet, until it leaves this machine.
- `MangleStatement::createSetCtMark($mark)` marks the connection, so every later packet in it has the mark.

```php
$ruleset->addRule(Rule::create($input, MangleStatement::createSetMetaMark(42), MangleStatement::createSetCtMark(7)));
```

```nft
meta mark set 0x0000002a ct mark set 0x00000007
```

For anything else, give it an expression and a value, e.g. `new MangleStatement(new MetaExpression(MetaKey::PRIORITY),
5)`, or a TCP option's field, to change it (see [MSS clamping](rules.md#mss-clamping)).

## Skipping connection tracking
A `NotrackStatement` exempts packets from connection tracking, e.g. for very busy traffic that doesn't need it. It only
works before tracking starts, so it belongs in a chain on the prerouting or output hook with `Priority::RAW`:

```php
$raw = new BaseChain("raw", $table, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW, Policy::ACCEPT);
$ruleset->addRule(Rule::create($raw, MatchFactory::createDestinationPorts(Protocol::UDP, 53), new NotrackStatement()));
```

```nft
udp dport 53 notrack
```

Untracked packets can't match `ct state established` or `related`, so rules that rely on those won't let them through.

## Synproxy
A `SynproxyStatement` protects a server from SYN floods. It answers new TCP connections itself, with SYN cookies, and
only passes a connection on to the server once the client has completed the handshake, so the flood (often from
spoofed addresses) never reaches the server, or fills conntrack. It only works in a filter chain on the input or
forward hook, and needs kernel 5.3, so isn't available on RHEL 8.

It needs three rules: SYN packets to the port skip conntrack, the synproxy takes the packets conntrack doesn't know
(`invalid` or `untracked`), and anything still invalid afterwards is dropped:

```php
$toWeb = MatchFactory::createDestinationPorts(Protocol::TCP, 443);
$untracked = MatchFactory::createConnectionStates(new ConnectionStateSet(ConnectionState::INVALID, ConnectionState::UNTRACKED));
$invalid = MatchFactory::createConnectionStates(new ConnectionStateSet(ConnectionState::INVALID));
$synproxy = new SynproxyStatement(1460, 7, SynproxyFlag::TIMESTAMP, SynproxyFlag::SACK_PERMITTED);

$ruleset->addRule(Rule::create($raw, $toWeb, MatchFactory::createTcpSyn(), new NotrackStatement()));
$ruleset->addRule(Rule::create($input, $toWeb, $untracked, $synproxy));
$ruleset->addRule(Rule::create($input, $invalid, Verdict::DROP));
```

```nft
tcp dport 443 tcp flags & (fin | syn | rst | ack) == syn notrack
tcp dport 443 ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm
ct state invalid drop
```

- The maximum segment size, window scale and flags are what the synproxy tells clients on the server's behalf, so
  they must match what the server would offer itself, or connections will misbehave. 1460 suits a server on
  Ethernet, and 7 is what Linux usually uses.
- The `net.netfilter.nf_conntrack_tcp_loose` sysctl must be 0, so conntrack marks the client's handshake reply as
  invalid, and the synproxy sees it.
- A [NamedSynproxy](objects.md#synproxies) shares the settings between several rules.

## Transparent proxying
A `TproxyStatement` sends packets to a proxy on this machine without changing their destination, so the proxy can see
where they were going, unlike a `RedirectStatement`. It only works in a filter chain on the prerouting hook, after a
match on the transport protocol (e.g. a port match):

```php
$mangle = new BaseChain("mangle", $table, ChainType::FILTER, ChainHook::PREROUTING, Priority::MANGLE, Policy::ACCEPT);
$toHttp = MatchFactory::createDestinationPorts(Protocol::TCP, 80);
$ruleset->addRule(Rule::create($mangle, $toHttp, MangleStatement::createSetMetaMark(1), TproxyStatement::createToAddress("127.0.0.1", 3128)));
```

```nft
tcp dport 80 meta mark set 0x00000001 tproxy to 127.0.0.1:3128
```

`TproxyStatement::createToPort()` keeps each packet's local address, and only gives the port. Either way, routing has
to deliver the packets locally, which is what the mark is for, and the proxy has to listen with `IP_TRANSPARENT`:

```bash
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

## Queueing to a program
A `QueueStatement` hands the packet to a program on this machine, e.g. an intrusion prevention system such as
Suricata, which decides whether it's accepted or dropped. What happens when no program is reading the queue (e.g.
while it restarts) has to be chosen:

- `QueueFailMode::DROP` drops the packets, so nothing gets through.
- `QueueFailMode::ACCEPT` accepts them, so traffic flows unchecked.

```php
$ruleset->addRule(Rule::create($input, QueueStatement::create(QueueFailMode::ACCEPT, 3)));
$ruleset->addRule(Rule::create($input, QueueStatement::createSpread(QueueFailMode::DROP, 4, 7)));
```

```nft
queue flags bypass to 3
queue flags fanout to 4-7
```

`createSpread()` spreads the packets across a range of queues, so several copies of the program can share the work.

## Adding to sets from rules (meters)
A `SetUpdateStatement` adds a value from the packet to a [named set](sets.md) (`SetUpdateOperation::ADD`), restarts
its timeout if it's already there (`UPDATE`), or removes it (`DELETE`). E.g. for port knocking, a connection attempt
to port 7000 remembers the address for 30 seconds, and SSH is only accepted from the addresses it remembers:

```php
$sourceAddress = PayloadExpression::create(PayloadField::IP_SADDR);
$knocked = NamedSet::create($table, "knocked", SetType::IPV4_ADDR)->withTimeout(30)->withSize(1000);
$addKnock = new SetUpdateStatement(SetUpdateOperation::ADD, $knocked, $sourceAddress);
$ruleset->addRule(Rule::create($input, MatchFactory::createDestinationPorts(Protocol::TCP, 7000), $addKnock));
$ruleset->addRule(Rule::create($input, MatchFactory::createDestinationPorts(Protocol::TCP, 22), MatchFactory::createInSet($sourceAddress, $knocked), Verdict::ACCEPT));
```

```nft
tcp dport 7000 add @knocked { ip saddr }
tcp dport 22 ip saddr @knocked accept
```

As traffic decides what goes in the set, adding or updating needs the set to have a size (`withSize()`), so packets
from spoofed addresses can't fill memory, and a timeout (`withTimeout()`), so old elements make room for new ones.
Creating one without them throws a `BadArgumentException`.

Each element can also carry its own counter, limit or quota, given after the element. That's what nft calls a meter:
e.g. to drop the new connections of any address that opens more than 10 a second, while other addresses are
unaffected. These need nft 1.0.6 (e.g. Debian 12), as older nft silently drops them:

```php
$ruleset = new Ruleset(NftablesTarget::DEBIAN_12);
$flood = NamedSet::create($table, "flood", SetType::IPV4_ADDR)->withTimeout(60)->withSize(65535);
$isNewConnection = MatchFactory::createConnectionStates(new ConnectionStateSet(ConnectionState::NEW));
$overLimit = new LimitStatement(10, LimitPeriod::SECOND, LimitMatch::OVER_LIMIT);
$ruleset->addRule(Rule::create($input, $isNewConnection, new SetUpdateStatement(SetUpdateOperation::UPDATE, $flood, $sourceAddress, $overLimit), Verdict::DROP));
```

```nft
ct state new update @flood { ip saddr limit rate over 10/second burst 5 packets } drop
```

A statement in the braces is applied to the packet, and the rule only carries on (here, to the drop) if it matches.
Once the set is full, the rule stops at the update until elements expire, so make the size comfortably bigger than the
number of addresses it should track at once.

## Statements covered elsewhere
- `VerdictMapStatement` looks a key up in a verdict map, and applies the verdict it maps to. See
  [verdict maps](maps.md#verdict-maps).
- `FlowOffloadStatement` offloads a connection to a flowtable's fast path. See [flowtables](flowtables.md).
- `NamedObjectStatement` uses a named counter, quota, limit, conntrack helper, conntrack timeout, synproxy or
  security mark. See [named objects](objects.md).

## Anything else
For a statement this package doesn't model yet (e.g. a connection limit), a `RawStatement` takes it in nft's JSON form,
exactly as the [libnftables-json
documentation](https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html) describes it:

```php
$ruleset->addRule(Rule::create($input, new RawStatement(["ct count" => ["val" => 20, "inv" => true]]), Verdict::DROP));
```

```nft
ct count over 20 drop
```

It's passed on without any checks, so check it loads with `nft --check`.
