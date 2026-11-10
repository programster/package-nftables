# Rules

- [Rules](#rules-1)
- [RuleFactory](#rulefactory)
  - [Accepting an interface](#accepting-an-interface)
  - [Opening a port](#opening-a-port)
  - [Port forwarding](#port-forwarding)
  - [Port forwarding from a map](#port-forwarding-from-a-map)
  - [Accepting port forwards](#accepting-port-forwards)
  - [Forwarding traffic through](#forwarding-traffic-through)
  - [Masquerading](#masquerading)
  - [Spotting spoofed packets](#spotting-spoofed-packets)
  - [MSS clamping](#mss-clamping)
  - [Flow offloading](#flow-offloading)
- [MatchFactory](#matchfactory)

The examples leave out `use` statements. Every class is in `Programster\Nftables`, or one of its `Enums`,
`Statements`, `Expressions` and `Exceptions` namespaces.

## Rules
A rule is a list of [statements](statements.md), applied to each packet in order. A match that the packet doesn't
pass skips the rest of the rule, and the packet moves on to the next one. So most rules are some matches, then a
verdict. `Rule::create()` takes the chain, then the statements:

```php
$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);

$isHttps = MatchFactory::createDestinationPorts(Protocol::TCP, 443);
$fromOffice = MatchFactory::createSourceAddress("198.51.100.0/24");
$rule = Rule::create($input, $isHttps, $fromOffice, new CounterStatement(), Verdict::ACCEPT);

$ruleset = new Ruleset();
$ruleset->addRule($rule->withComment("HTTPS from the office"));
```

```nft
tcp dport 443 ip saddr 198.51.100.0/24 counter packets 0 bytes 0 accept comment "HTTPS from the office"
```

- A rule needs at least one statement. (nft accepts an empty rule, which does nothing.)
- `withComment()` gives a copy of the rule with a comment, which shows in `nft list ruleset`. It can be at most 128
  bytes, the most nft handles.
- The statements are typed, so passing anything else (e.g. a raw array of nft's JSON) is a `TypeError`. For a
  statement this package doesn't model yet, use a [`RawStatement`](statements.md#anything-else).
- A rule can use any statement, so it doesn't have to end with a verdict: e.g. one that only logs or counts lets the
  packet carry on to the next rule.

## RuleFactory
`RuleFactory` creates the rules a typical firewall or NAT gateway needs. Each one checks it's being added to a suitable
chain (throwing an `UnsuitableChainException` if not), and ends with a verdict, so it always does something. Their
optional parameters are best passed by name.

The examples below use these chains:

```php
$table = new Table("gateway", Family::IP);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::DROP);
$prerouting = new BaseChain("prerouting", $table, ChainType::NAT, ChainHook::PREROUTING, Priority::DSTNAT, Policy::ACCEPT);
$postrouting = new BaseChain("postrouting", $table, ChainType::NAT, ChainHook::POSTROUTING, Priority::SRCNAT, Policy::ACCEPT);
$ruleset = new Ruleset();
```

### Accepting an interface
`createAcceptInterface()` accepts everything arriving on an interface, optionally only in some connection states:

```php
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);
$ruleset->addRule(RuleFactory::createAcceptInterface($input, "lo"));
$ruleset->addRule(RuleFactory::createAcceptInterface($input, "eth0", $replies, "replies to our own connections"));
```

```nft
iifname "lo" accept
iifname "eth0" ct state established,related accept comment "replies to our own connections"
```

### Opening a port
`createAcceptPort()` accepts traffic to a port, ports (a `PortSet`) or a range of ports (a `PortRange`) on this
machine. It can also check where the traffic comes from, which of the machine's addresses it's going to, and its
connection state:

```php
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", new PortSet(80, 443)));
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", 22, sourceAddress: "198.51.100.0/24"));
$ruleset->addRule(RuleFactory::createAcceptPort($input, "eth0", 51820, Protocol::UDP, destinationAddress: "203.0.113.1"));
```

```nft
iifname "eth0" tcp dport { 80, 443 } accept
iifname "eth0" tcp dport 22 ip saddr 198.51.100.0/24 accept
iifname "eth0" udp dport 51820 ip daddr 203.0.113.1 accept
```

### Port forwarding
`createPortForward()` sends traffic arriving on a port (or range of ports) on to another machine, typically one behind
this one. Its new destination port defaults to the port it arrived on:

```php
$ruleset->addRule(RuleFactory::createPortForward($prerouting, "eth0", 8443, "10.0.0.10", 443));
$ruleset->addRule(RuleFactory::createPortForward($prerouting, "eth0", new PortRange(5000, 5100), "10.0.0.11", protocol: Protocol::UDP));
```

```nft
iifname "eth0" tcp dport 8443 dnat to 10.0.0.10:443
iifname "eth0" udp dport 5000-5100 dnat to 10.0.0.11
```

A range of ports can only be forwarded to the same ports (by leaving out the new port, as above, or giving the same
range). Forwarding one range to a different range, or one port to a range, throws a `BadArgumentException`: nft would
send every connection to whichever port in the range it picked, not map them across one to one.

This only changes the destination. Unless the forward chain's policy is accept, the traffic also needs letting through
it, with `createForward()`.

### Port forwarding from a map
`createMapPortForward()` does many port forwards in one rule, with the forwards as the elements of a named
[map](maps.md), rather than a rule each. A gateway with dozens of forwards then has one rule per protocol (and
allowlist), and a forward can be added or removed at runtime with `nft add element`, without reloading. Each forward
is a `PortForward` of an incoming port, an address and a port, in a `PortForwardCollection`:

```php
$forwards = new PortForwardCollection([new PortForward(2222, "10.0.0.2", 22), new PortForward(8080, "10.0.0.3", 80)]);
$ruleset->addRule(RuleFactory::createMapPortForward($prerouting, "eth0", "forwards", PortForwardMapLayout::TWO_MAPS, IpVersion::IPV4, $forwards));
```

```nft
map forwards_addresses {
	type inet_service : ipv4_addr
	elements = { 2222 : 10.0.0.2,
		     8080 : 10.0.0.3 }
}

map forwards_ports {
	type inet_service : inet_service
	elements = { 2222 : 22,
		     8080 : 80 }
}

iifname "eth0" dnat to tcp dport map @forwards_addresses:tcp dport map @forwards_ports
```

The layout has to be chosen, as it depends on the [target](targets.md):

| `PortForwardMapLayout` | Maps | Needs | To add a forward at runtime |
|---|---|---|---|
| `ONE_MAP` | `forwards`, from port to address and port together, e.g. `2222 : 10.0.0.2 . 22` | nft 1.1.3 (e.g. Debian 13), or RHEL 9 | `nft add element ip gateway forwards '{ 2223 : 10.0.0.5 . 22 }'` |
| `TWO_MAPS` | `forwards_addresses`, from port to address, and `forwards_ports`, from port to port | nft 0.9.8, so every target | The same in each map: `'{ 2223 : 10.0.0.5 }'` and `'{ 2223 : 22 }'` |

With `ONE_MAP` and an older target, adding the rule throws an `UnsupportedFeatureException`. Its optional parameters
are:

| Parameter | Default | Use |
|---|---|---|
| `$protocol` | `Protocol::TCP` | The transport protocol. UDP forwards need their own rule, with their own map name. |
| `$allowedSources` | `null` (anywhere) | A [named set](sets.md) of the addresses the traffic must come from, e.g. an allowlist for SSH |
| `$destinationAddress` | `null` (any) | The address the traffic must have been sent to, for a machine with more than one |
| `$comment` | `""` | A comment for the rule |

E.g. for forwards that only a few trusted addresses can use, alongside the public ones above:

```php
$trusted = NamedSet::createAddressSet($table, "trusted", IpVersion::IPV4, "198.51.100.7", "203.0.113.0/24");
$private = new PortForwardCollection([new PortForward(22, "10.0.0.4", 22)]);
$ruleset->addRule(RuleFactory::createMapPortForward($prerouting, "eth0", "private", PortForwardMapLayout::TWO_MAPS, IpVersion::IPV4, $private, allowedSources: $trusted));
```

```nft
iifname "eth0" ip saddr @trusted dnat to tcp dport map @private_addresses:tcp dport map @private_ports
```

A port that isn't in the maps isn't forwarded, so the packet carries on to this machine's own input chain. As with
`createPortForward()`, the forwarded traffic also needs accepting in the forward chain, unless its policy is accept:
see [accepting port forwards](#accepting-port-forwards).

### Accepting port forwards
`createAcceptPortForwards()` accepts every connection that was port forwarded (`ct status dnat`), in both directions,
so a forward chain with a drop policy lets them through without a rule for each. It only accepts what a rule in a nat
chain chose to forward, so it doesn't open anything else:

```php
$ruleset->addRule(RuleFactory::createAcceptPortForwards($forward));
```

```nft
ct status dnat accept
```

### Forwarding traffic through
`createForward()` accepts traffic passing through this machine from one interface to another. For a port forward,
that's usually the new connections going in, and the replies to them:

```php
$new = new ConnectionStateSet(ConnectionState::NEW);
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);
$ruleset->addRule(RuleFactory::createForward($forward, "eth0", "eth1", $new, destinationPorts: 443, destinationAddress: "10.0.0.10", requireTcpSyn: true));
$ruleset->addRule(RuleFactory::createForward($forward, "eth0", "eth1", $replies));
$ruleset->addRule(RuleFactory::createForward($forward, "eth1", "eth0"));
```

```nft
iifname "eth0" oifname "eth1" ip daddr 10.0.0.10 tcp dport 443 ct state new tcp flags & (fin | syn | rst | ack) == syn accept
iifname "eth0" oifname "eth1" ct state established,related accept
iifname "eth1" oifname "eth0" accept
```

`requireTcpSyn` only accepts TCP packets that start a connection properly (SYN set, and FIN, RST and ACK not), so a
packet can't get through by claiming to be new. It's only for TCP, so it throws a `BadArgumentException` with any other
protocol.

### Masquerading
`createMasquerade()` makes traffic leaving by an interface appear to come from this machine, so machines behind it can
reach the internet through its address:

```php
$ruleset->addRule(RuleFactory::createMasquerade($postrouting, "eth0"));
```

```nft
oifname "eth0" masquerade
```

### Spotting spoofed packets
`createReversePathFilter()` drops packets that couldn't have arrived on the interface they did: ones whose source
address this machine wouldn't route back out of that interface. That's how packets with spoofed source addresses are
spotted. It belongs early on, in a filter chain on the prerouting hook:

```php
$early = new BaseChain("early", $table, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW, Policy::ACCEPT);
$ruleset->addRule(RuleFactory::createReversePathFilter($early));
```

```nft
fib saddr . iif oif missing drop
```

Only use it where traffic really is symmetric: a machine with several routes to the same network (e.g. two internet
connections) can receive legitimate packets on an interface it wouldn't route replies out of.

### MSS clamping
`createMssClamp()` lowers the maximum segment size that TCP connections passing through this machine ask for, to fit
the MTU of their route. Without it, connections through a link with a smaller MTU than usual (e.g. a VPN, or PPPoE)
can hang as soon as they send a full sized packet:

```php
$ruleset->addRule(RuleFactory::createMssClamp($forward));
```

```nft
tcp flags syn tcp option maxseg size set rt mtu
```

### Flow offloading
`createFlowOffload()` offloads forwarded TCP and UDP connections to a [flowtable](flowtables.md), a fast path that
makes forwarding much cheaper. Flowtables need nft 1.0.6, so the ruleset needs a target that has it:

```php
$ruleset = new Ruleset(NftablesTarget::DEBIAN_12);
$ruleset->addRule(RuleFactory::createFlowOffload($forward, new Flowtable("fastpath", $table, Priority::FILTER, "eth0", "eth1")));
```

```nft
meta l4proto { tcp, udp } flow add @fastpath
```

## MatchFactory
`MatchFactory` creates the common [matches](statements.md#matches). The ones that take a `MatchMode` can be negated
with `MatchMode::DOES_NOT_MATCH`, and the address ones work out IPv4 or IPv6 from the address:

| Method | Matches | e.g. |
|---|---|---|
| `createInputInterfaceName($name)` | The interface it arrived on | `iifname "eth0"` |
| `createOutputInterfaceName($name)` | The interface it's leaving by | `oifname "eth0"` |
| `createDestinationPorts($protocol, $ports)` | Its destination port(s): an `int`, `PortSet` or `PortRange` | `tcp dport { 80, 443 }` |
| `createSourcePorts($protocol, $ports)` | Its source port(s) | `udp sport 53` |
| `createSourceAddress($addressOrCidr)` | Where it came from: an address or network | `ip saddr 10.0.0.0/8` |
| `createDestinationAddress($addressOrCidr)` | Where it's going | `ip6 daddr fd00::1` |
| `createInSet($left, $set)` | Something in it, against a [named set](sets.md) | `ip saddr @blocklist` |
| `createConnectionStates($states)` | Its connection's state | `ct state established,related` |
| `createTransportProtocol($protocol)` | Its transport protocol, in either IP version | `meta l4proto udp` |
| `createTcpSyn()` | The start of a TCP connection | `tcp flags & (fin \| syn \| rst \| ack) == syn` |
| `createExistence($left, $existence)` | Whether it has something: see [existence checks](expressions.md#existence-checks) | `exthdr frag exists` |

```php
$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$invalid = new ConnectionStateSet(ConnectionState::INVALID);

$ruleset = new Ruleset();
$ruleset->addRule(Rule::create($input, MatchFactory::createConnectionStates($invalid), Verdict::DROP));
$ruleset->addRule(Rule::create($input, MatchFactory::createSourceAddress("fd00::/8", MatchMode::DOES_NOT_MATCH), Verdict::DROP));
```

```nft
ct state invalid drop
ip6 saddr != fd00::/8 drop
```

An address must be a single address or a *network* CIDR, with its host bits all zero, as nft needs. Anything else
throws an `InvalidAddressException`, which suggests the network for a host CIDR:

```php
// Throws InvalidAddressException
// "192.168.0.1/24 has host bits set. Did you mean the network 192.168.0.0/24?"
MatchFactory::createSourceAddress("192.168.0.1/24");
```
