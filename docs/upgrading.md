# Upgrading

- [From 1.0.0-alpha2](#from-100-alpha2)
- [From 1.0.0-alpha1](#from-100-alpha1)
- [From 0.x](#from-0x)
  - [Things that behave differently](#things-that-behave-differently)
  - [Renamed classes](#renamed-classes)
  - [Renamed enums](#renamed-enums)
  - [Renamed exceptions](#renamed-exceptions)
  - [RuleFactory](#rulefactory)
  - [MatchFactory](#matchfactory)
  - [Everything else](#everything-else)

## From 1.0.0-alpha2
Nothing needs changing. `PerSourceConnectionLimits` can now exempt some addresses from its limits, with
`exemptSources` (see [limiting connections per source](rules.md#limiting-connections-per-source)).

## From 1.0.0-alpha1
- **`RuleFactory::createPerSourceConnectionLimits()` takes a `PerSourceConnectionLimits`**, rather than the set name,
  the limits and `$maxSources` separately: `createPerSourceConnectionLimits($chain, $inputInterfaceName,
  $destinationAddress, $ports, $limits, $protocol, $comment)`, with
  `new PerSourceConnectionLimits($maxConnections, $rates, $name, $maxSources)`. The rate is now a
  `ConnectionRateLimit($maxNewConnections, $period)`, in a `ConnectionRateLimitCollection`, so there can be several,
  e.g. one a minute and one an hour, and the maximum open at once is optional. The rate's set is now named
  `<name>_per_<period>` (e.g. `smtp_per_minute`), rather than `<name>_rate`. Pass the same limits object to share one
  count per address between rules, e.g. across a server's ports. Its name is optional, and two objects can't have the
  same one. See [limiting connections per source](rules.md#limiting-connections-per-source).

## From 0.x

1.0 renames nearly everything, so an upgrade is mostly a search and replace, but a few things also behave
differently. Read those first.

### Things that behave differently
- **Forwarding rules now accept.** `createForwardingRule()` built a rule with no verdict, which matched packets but did
  nothing with them. Its replacement, `createForward()`, ends with accept. If you added the rules it built, they now
  let traffic through.
- **A forwarding rule's destination address works.** `createForwardingRule()` matched `$destIpOrCidr` against the
  *source* address, or threw a `TypeError` if only a destination was given.
- **IPv6 addresses work.** Address matches always used the IPv4 header, which nft rejects in an `ip6` table. They now
  use whichever the address is.
- **Ports are checked.** A port outside 1 to 65535 throws a `BadArgumentException`, instead of nft failing later with
  "Service out of range". `new PortRange(80, 80)` still throws, as before, but with a `BadArgumentException` instead
  of a plain `Exception`.
- **Duplicate ports and connection states** give a JSON list, rather than a JSON object with gaps in its keys.
- **Rules take statements, not arrays.** `new NftablesRule($chain, [...], $comment)` becomes
  `Rule::create($chain, ...$statements)->withComment($comment)`, and each statement is a typed `Statement` object, so
  a raw array such as `["accept" => null]` becomes `Verdict::ACCEPT`. Anything this package doesn't model can go in a
  `RawStatement`.
- **Comments are strings.** A rule's comment is set with `withComment()`, and the factories' `$comment` parameters
  default to `""` (none), rather than `null`.
- **`toArray()` is plain arrays** all the way down. A rule's `toArray()` used to contain match objects.
- **The metainfo block** only gives the JSON schema version. It used to claim to be from nft 1.0.6.
- **Rulesets have a target.** A `Ruleset` refuses anything its [target](targets.md) can't load. The default is the
  oldest supported nft (0.9.8), which everything 0.x could do still works on, so pass a target only to use the few
  features that need a newer one.
- **Collections can't be changed.** The typed collections (e.g. `Collections\SetTypeCollection`) are readonly, from
  [programster/collections](https://github.com/programster/package-collections). They take their elements as
  arguments, e.g. `new SetTypeCollection(SetType::IPV4_ADDR, SetType::INET_SERVICE)`, and have no `add()`. Use
  `merge()` to get a new collection with more elements.

### Renamed classes
1.0's classes are grouped into namespaces under `Programster\Nftables` (see
[namespaces](getting-started.md#namespaces)), so the names below include them, e.g. `Tables\Table` is
`Programster\Nftables\Tables\Table`. Only `Ruleset` is at the top.

| 0.x | 1.0 |
|---|---|
| `NftablesTable` | `Tables\Table` (same arguments) |
| `NftablesChain` | `Chains\BaseChain` (same arguments, and the priority can now be any integer) |
| `NftablesRule` | `Rules\Rule::create()` (takes `Statement`s, see above) |
| `NftablesRuleset` | `Ruleset`, which is now readonly: everything goes to its constructor, `new Ruleset($rules, $target, $resetMode, $emptyChains, $emptyTables)`, so pass the reset mode by name (`resetMode: ...`) or third. See [building a ruleset](rulesets.md#building-a-ruleset). |
| `NftablesRuleset::addRule(...$rules)`, `addTable()` and `addChain()` | The constructor's `$rules` (a `Collections\RuleCollection`). Rules bring their chains, and chains their tables, so `addChain()` is only needed for a base chain with no rules (`$emptyChains`), and `addTable()` for an empty table (`$emptyTables`). |
| `NftablesMatch` | `Statements\MatchStatement` (the left side must now be an `Expression`) |
| `NftablesConnectionStateCollection` | `Sets\ConnectionStateSet` |
| `NftablesRuleFactory` | `Helpers\RuleFactory` (see below) |
| `NftablesMatchFactory` | `Helpers\MatchFactory` (see below) |
| `NftablesLib::createDnat()` | `Statements\DnatStatement::create($address, $port)` |
| `NftablesLib::createMetaInfoBlock()` | Removed: `Ruleset` adds it |
| `NftablesLib::isValidCidr()`, `isValidNetworkCidr()` | `Helpers\NetworkLib::isValidCidr()`, `isValidNetworkCidr()` |
| `PortRange::$minPort`, `$maxPort` | `Sets\PortRange::getMinPort()`, `getMaxPort()` |

### Renamed enums
| 0.x | 1.0 |
|---|---|
| `NftablesFamily` | `Family` |
| `NftablesChainType` | `ChainType` |
| `NftablesChainHook` | `ChainHook` |
| `NftablesPolicy` | `Policy` |
| `NftablesConnectionState` | `ConnectionState` (adds `INVALID`) |
| `NftablesMatchOperator` | `Operator` (adds `NOT_EQUALS`, `LESS_THAN` and the rest) |
| `NftablesRulesetResetMode` | `RulesetResetMode` |
| `NftablesVerdict` | `Verdict`. `QUEUE`, `JUMP` and `GO_TO` are now `QueueStatement`, `JumpStatement` and `GotoStatement`, as they need more than a name. |
| `Protocol` | `Protocol` (adds `UDPLITE`, `SCTP` and `DCCP`) |
| `NftablesPriority` | `Priority`, with nft's names (see below) |

| `NftablesPriority` | `Priority`, or the integer |
|---|---|
| `NF_IP_PRI_RAW` | `RAW` |
| `NF_IP_PRI_MANGLE` | `MANGLE` |
| `NF_IP_PRI_NAT_DST` | `DSTNAT` |
| `NF_IP_PRI_FILTER` | `FILTER` |
| `NF_IP_PRI_SECURITY` | `SECURITY` |
| `NF_IP_PRI_NAT_SRC` | `SRCNAT` |
| `NF_IP_PRI_CONNTRACK_DEFRAG` | `-400` |
| `NF_IP_PRI_SELINUX_FIRST` | `-225` |
| `NF_IP_PRI_CONNTRACK` | `-200` |
| `NF_IP_PRI_SELINUX_LAST` | `225` |
| `NF_IP_PRI_CONNTRACK_HELPER` | `300` |

### Renamed exceptions
| 0.x | 1.0 |
|---|---|
| `ExceptionChainConflict` | `ConflictException` |
| `ExceptionUnsuitableChain` | `UnsuitableChainException` |
| `ExceptionInvalidNetworkCidr` | `InvalidAddressException` |
| `ExceptionPortRequired`, `ExceptionConnectionStateRequired` | `BadArgumentException` |
| `ExceptionPortTaken` | Removed (it was never thrown) |

Every exception now implements `NftablesException`, and a few places that threw a plain `Exception` throw one of these
instead. See [Errors](errors.md).

### RuleFactory
The chain always comes first now, and the parameters have clearer names, which matters if you pass them by name.

| 0.x | 1.0 |
|---|---|
| `createAcceptNetworkInterfaceInput($interfaceName, $inputChain, $allowedStates, $comment)` | `createAcceptInterface($inputChain, $interfaceName, $states, $comment)` |
| `createAcceptPort($inputFilterChain, $interfaceName, $incomingPortOrPorts, $protocol, $destIpOrCidr, $sourceIpOrCidr, $allowedStates, $comment)` | `createAcceptPort($inputChain, $interfaceName, $ports, $protocol, $destinationAddress, $sourceAddress, $states, $comment)` |
| `createPortForwardNatRule($preroutingChain, $inputInterfaceName, $inputPort, $newDestIp, $newDestPort, $protocol, $sourceIpCidr, $destIpCidr, $comment)` | `createPortForward($preroutingChain, $inputInterfaceName, $incomingPorts, $newDestinationAddress, $newDestinationPorts, $protocol, $sourceAddress, $destinationAddress, $comment)` |
| `createPortRangeForwardNatRule($preroutingChain, $inputInterfaceName, $inputPorts, $newDestIp, $destPorts, $protocol, $sourceIpCidr, $comment)` | `createPortForward()`, with `PortRange`s. The new ports can be left out, to keep each packet's port. |
| `createForwardingRule($forwardFilteringChain, $inputInterface, $outputInterface, $checkForSynPacketType, $allowedStates, $protocol, $destPort, $sourceIpOrCidr, $destIpOrCidr, $comment)` | `createForward($forwardChain, $inputInterfaceName, $outputInterfaceName, $states, $protocol, $destinationPorts, $sourceAddress, $destinationAddress, $requireTcpSyn, $comment)`. The SYN check is now an optional named parameter near the end. |
| `createMasquerade($postRoutingChain, $outputInterfaceName, $comment)` | `createMasquerade($postroutingChain, $outputInterfaceName, $ipVersion, $sourceAddress, $destinationAddress, $comment)`. A comment passed by position now goes sixth, so pass it by name. The addresses can make it a [hairpin NAT](rules.md#masquerading). |

`createPortForward()` now refuses to forward a range of ports to a different range, which nft can't do one to one, and
`createForward()` refuses a SYN check on anything but TCP.

### MatchFactory
| 0.x | 1.0 |
|---|---|
| `createMatchDestinationPorts($protocol, ...$ports)` | `createDestinationPorts($protocol, $ports)`, with an `int`, `PortSet` or `PortRange` |
| `createMatchDestinationPortRange($protocol, $range)` | `createDestinationPorts($protocol, $range)` |
| `createMatchInputInterfaceName($name)` | `createInputInterfaceName($name)` |
| `createMatchOutputInterfaceName($name)` | `createOutputInterfaceName($name)` |
| `createMatchSourceIpOrCidr($ipOrCidr)` | `createSourceAddress($addressOrCidr)` |
| `createMatchDestinationIpOrCidr($ipOrCidr)` | `createDestinationAddress($addressOrCidr)` |
| `createMatchConnectionStates(...$states)` | `createConnectionStates(new ConnectionStateSet(...$states))` |
| `createMatchTcpSynFlag()` | `createTcpSyn()` |

Most of them now take a `MatchMode`, to negate them, and there are new ones: `createSourcePorts()`, `createInSet()`,
`createTransportProtocol()` and `createIcmpv6Types()`.

### Everything else
New in 1.0, and covered in the rest of the docs: [targets](targets.md),
[regular chains](tables-and-chains.md#regular-chains) with jumps and gotos, [named sets](sets.md),
[maps and verdict maps](maps.md), [flowtables](flowtables.md), [named objects](objects.md) (counters, quotas, limits,
conntrack helpers, timeouts and expectations, synproxies and security marks), table flags, the bridge, ARP and netdev
families, and the [statements](statements.md) and [expressions](expressions.md) beyond matching and NAT: reject,
log, counter, limit, quota, connection limits, queue, notrack, marks, snat and redirect, synproxy, transparent
proxying, adding to sets from rules (meters), dup and fwd, existence checks, fib and rt lookups, sockets, IPsec,
IPv6 extension headers, TCP options and SCTP chunks, number generators and hashes, OS fingerprinting, and rules for
spotting spoofed packets, clamping the MSS, offloading to a flowtable, port forwarding from a map, accepting port
forwards, accepting essential ICMPv6 and [limiting connections per source](rules.md#limiting-connections-per-source).
There are also complete [examples](examples.md).
