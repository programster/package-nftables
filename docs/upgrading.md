# Upgrading from 0.x

- [Things that behave differently](#things-that-behave-differently)
- [Renamed classes](#renamed-classes)
- [Renamed enums](#renamed-enums)
- [Renamed exceptions](#renamed-exceptions)
- [RuleFactory](#rulefactory)
- [MatchFactory](#matchfactory)
- [Everything else](#everything-else)

1.0 renames nearly everything, so an upgrade is mostly a search and replace, but a few things also behave
differently. Read those first.

## Things that behave differently
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

## Renamed classes
| 0.x | 1.0 |
|---|---|
| `NftablesTable` | `Table` (same arguments) |
| `NftablesChain` | `BaseChain` (same arguments, and the priority can now be any integer) |
| `NftablesRule` | `Rule::create()` (takes `Statement`s, see above) |
| `NftablesRuleset` | `Ruleset`, whose first parameter is now the [target](targets.md), so pass the reset mode by name (`new Ruleset(resetMode: ...)`) or second |
| `NftablesMatch` | `Statements\MatchStatement` (the left side must now be an `Expression`) |
| `NftablesConnectionStateCollection` | `ConnectionStateSet` |
| `NftablesRuleFactory` | `RuleFactory` (see below) |
| `NftablesMatchFactory` | `MatchFactory` (see below) |
| `NftablesLib::createDnat()` | `Statements\DnatStatement::create($address, $port)` |
| `NftablesLib::createMetaInfoBlock()` | Removed: `Ruleset` adds it |
| `NftablesLib::isValidCidr()`, `isValidNetworkCidr()` | `NetworkLib::isValidCidr()`, `isValidNetworkCidr()` |
| `PortRange::$minPort`, `$maxPort` | `PortRange::getMinPort()`, `getMaxPort()` |

## Renamed enums
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

## Renamed exceptions
| 0.x | 1.0 |
|---|---|
| `ExceptionChainConflict` | `ConflictException` |
| `ExceptionUnsuitableChain` | `UnsuitableChainException` |
| `ExceptionInvalidNetworkCidr` | `InvalidAddressException` |
| `ExceptionPortRequired`, `ExceptionConnectionStateRequired` | `BadArgumentException` |
| `ExceptionPortTaken` | Removed (it was never thrown) |

Every exception now implements `NftablesException`, and a few places that threw a plain `Exception` throw one of these
instead. See [Errors](errors.md).

## RuleFactory
The chain always comes first now, and the parameters have clearer names, which matters if you pass them by name.

| 0.x | 1.0 |
|---|---|
| `createAcceptNetworkInterfaceInput($interfaceName, $inputChain, $allowedStates, $comment)` | `createAcceptInterface($inputChain, $interfaceName, $states, $comment)` |
| `createAcceptPort($inputFilterChain, $interfaceName, $incomingPortOrPorts, $protocol, $destIpOrCidr, $sourceIpOrCidr, $allowedStates, $comment)` | `createAcceptPort($inputChain, $interfaceName, $ports, $protocol, $destinationAddress, $sourceAddress, $states, $comment)` |
| `createPortForwardNatRule($preroutingChain, $inputInterfaceName, $inputPort, $newDestIp, $newDestPort, $protocol, $sourceIpCidr, $destIpCidr, $comment)` | `createPortForward($preroutingChain, $inputInterfaceName, $incomingPorts, $newDestinationAddress, $newDestinationPorts, $protocol, $sourceAddress, $destinationAddress, $comment)` |
| `createPortRangeForwardNatRule($preroutingChain, $inputInterfaceName, $inputPorts, $newDestIp, $destPorts, $protocol, $sourceIpCidr, $comment)` | `createPortForward()`, with `PortRange`s. The new ports can be left out, to keep each packet's port. |
| `createForwardingRule($forwardFilteringChain, $inputInterface, $outputInterface, $checkForSynPacketType, $allowedStates, $protocol, $destPort, $sourceIpOrCidr, $destIpOrCidr, $comment)` | `createForward($forwardChain, $inputInterfaceName, $outputInterfaceName, $states, $protocol, $destinationPorts, $sourceAddress, $destinationAddress, $requireTcpSyn, $comment)`. The SYN check is now an optional named parameter near the end. |
| `createMasquerade($postRoutingChain, $outputInterfaceName, $comment)` | `createMasquerade($postroutingChain, $outputInterfaceName, $ipVersion, $comment)`. A comment passed by position now goes fourth, or by name. |

`createPortForward()` now refuses to forward a range of ports to a different range, which nft can't do one to one, and
`createForward()` refuses a SYN check on anything but TCP.

## MatchFactory
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

## Everything else
New in 1.0, and covered in the rest of the docs: [targets](targets.md),
[regular chains](tables-and-chains.md#regular-chains) with jumps and gotos, [named sets](sets.md),
[maps and verdict maps](maps.md), [flowtables](flowtables.md), [named objects](objects.md) (counters, quotas, limits,
conntrack helpers, timeouts and expectations, synproxies and security marks), table flags, the bridge, ARP and netdev
families, and the [statements](statements.md) and [expressions](expressions.md) beyond matching and NAT: reject,
log, counter, limit, quota, connection limits, queue, notrack, marks, snat and redirect, synproxy, transparent
proxying, adding to sets from rules (meters), dup and fwd, existence checks, fib and rt lookups, sockets, IPsec,
IPv6 extension headers, TCP options and SCTP chunks, number generators and hashes, OS fingerprinting, and rules for
spotting spoofed packets, clamping the MSS, offloading to a flowtable, port forwarding from a map, accepting port
forwards and accepting essential ICMPv6. There are also complete [examples](examples.md).
