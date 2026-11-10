# Examples

- [A NAT gateway with port forwards](#a-nat-gateway-with-port-forwards)
  - [What it lets through](#what-it-lets-through)
  - [Setting up the gateway](#setting-up-the-gateway)
  - [Things to know](#things-to-know)
  - [Taking it further: adding IPv6](#taking-it-further-adding-ipv6)
- [The same gateway, with its forwards in maps](#the-same-gateway-with-its-forwards-in-maps)
- [A web server](#a-web-server)

Complete rulesets for common setups, each tested against real nft like every example in these docs. They use
addresses reserved for documentation (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24` and `2001:db8::/32`), so
replace them with your own.

## A NAT gateway with port forwards
A gateway (e.g. a VM in Proxmox) with two network interfaces: `eth0` on the internet, with the one public IPv4
address, and `eth1` on a LAN of guests. The guests reach the internet through it, NATed behind its address, and the
internet reaches them through port forwards: 80 and 443 to the web proxy (TCP for HTTP and HTTPS, and UDP 443 for
HTTP/3), and an SSH port for each guest (2210 to 2212), which only your trusted address can use. That's `$trustedIp`,
the static IP address you manage the servers from, e.g. your office's.

| Guest | Address | Reachable from the internet |
|---|---|---|
| Web proxy | `10.0.0.10` | HTTP, HTTPS and HTTP/3 from anywhere (TCP 80 and 443, and UDP 443), and SSH from the trusted address (port 2210) |
| App server | `10.0.0.11` | SSH from the trusted address (port 2211) |
| Database | `10.0.0.12` | SSH from the trusted address (port 2212) |

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

### What it lets through
Both chains that filter (input and forward) have a drop policy, so anything no rule accepts is dropped:

| Traffic | What happens |
|---|---|
| Guests to the internet | Masqueraded, so it comes from the gateway's address |
| Replies to the guests | Accepted, as `ct state established,related` |
| Internet to TCP 80 and 443, and UDP 443 | Port forwarded to the web proxy, then accepted by `ct status dnat` |
| The trusted address to ports 2210 to 2212 | Port forwarded to that guest's port 22, then accepted the same way |
| Anyone else to ports 2210 to 2212 | Not forwarded, so it reaches the gateway's own input chain, and is dropped |
| Anything else from the internet | Dropped |
| The LAN to the gateway | Accepted |
| IPv6, other than on the LAN and loopback | Dropped, as nothing accepts it. See [adding IPv6](#taking-it-further-adding-ipv6). |

`ct status dnat` accepts any connection a rule in the prerouting chain port forwarded, so each forward doesn't need a
rule in the forward chain too. A connection is only forwarded if a forward chose to, so this doesn't open anything
else. A forward with an allowlist (like the SSH ones) only forwards connections from those addresses, so the rest are
never forwarded, and never accepted.

### Setting up the gateway
The ruleset only filters. The gateway also needs:

- **Forwarding switched on**, e.g. with `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/90-gateway.conf`.
- **The guests using it as their gateway**: `10.0.0.1`, or whatever the gateway's LAN address is.

### Things to know
- **The LAN is trusted.** `iifname "eth1" accept` lets the guests reach anything on the gateway itself. Drop it, and
  accept just what they need (e.g. DNS), if the guests aren't trusted.
- **The guests can't reach the forwards at the public address.** A guest connecting to the gateway's public address
  arrives on `eth1`, not `eth0`, so the forwards don't apply. Reach each other at their LAN addresses instead.
- **With many forwards**, a rule each gets long. See [the same gateway, with its forwards in
  maps](#the-same-gateway-with-its-forwards-in-maps).

### Taking it further: adding IPv6
With IPv6, each guest can have a public address of its own, e.g. from a `2001:db8:0:1::/64` network routed to the
gateway. Nothing is NATed for IPv6: the gateway routes the guests' traffic, and its forward chain decides what reaches
them, the same as for IPv4.

| Guest | IPv4 | IPv6 | Reachable over IPv6 |
|---|---|---|---|
| Web proxy | `10.0.0.10` | `2001:db8:0:1::10` | HTTP, HTTPS and HTTP/3 from anywhere, and SSH from the trusted address, at port 22 of its own address |
| App server | `10.0.0.11` | `2001:db8:0:1::11` | SSH from the trusted address |
| Database | `10.0.0.12` | `2001:db8:0:1::12` | SSH from the trusted address |

Compared with the IPv4 gateway, this:

- masquerades IPv4 only (`IpVersion::IPV4`), so the guests' IPv6 traffic keeps their own addresses
- accepts the [ICMPv6 that IPv6 can't work without](rules.md#accepting-essential-icmpv6), in the input and forward
  chains. Unlike ICMP for IPv4, it isn't optional.
- accepts the web proxy's HTTP, HTTPS and HTTP/3, and SSH from the trusted address to each guest, in the forward chain,
  as there's no port forward for them to go through
- lets your trusted IPv6 network SSH to the gateway too. That's `$trustedIpv6Network`, as an office's IPv6 is
  usually a whole network, e.g. a /48 or /56, whose machines' addresses change over time.

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

Load it with `nft --json --file /etc/gateway/ruleset.json`, and `nft list ruleset` shows:

```nft
table inet gateway {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "eth1" accept
		iifname "eth0" ct state established,related accept
		icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept
		iifname "eth0" tcp dport 22 ip saddr 198.51.100.7 accept comment "SSH to the gateway"
		iifname "eth0" tcp dport 22 ip6 saddr 2001:db8:ffff::/48 accept comment "SSH to the gateway"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "eth1" oifname "eth0" accept
		iifname "eth0" oifname "eth1" ct state established,related accept
		icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
		iifname "eth0" oifname "eth1" ip6 daddr 2001:db8:0:1::10 tcp dport { 80, 443 } accept
		iifname "eth0" oifname "eth1" ip6 daddr 2001:db8:0:1::10 udp dport 443 accept
		iifname "eth0" oifname "eth1" ip6 saddr 2001:db8:ffff::/48 ip6 daddr 2001:db8:0:1::10 tcp dport 22 accept
		iifname "eth0" oifname "eth1" ip6 saddr 2001:db8:ffff::/48 ip6 daddr 2001:db8:0:1::11 tcp dport 22 accept
		iifname "eth0" oifname "eth1" ip6 saddr 2001:db8:ffff::/48 ip6 daddr 2001:db8:0:1::12 tcp dport 22 accept
		ct status dnat accept
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" meta nfproto ipv4 masquerade
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


| Traffic | IPv4 | IPv6 |
|---|---|---|
| Guests to the internet | Masqueraded, so it comes from the gateway's address | Routed, from the guest's own address |
| Internet to the web proxy, TCP 80 and 443, and UDP 443 | Port forwarded | Sent to its own address, and accepted by the `ip6 daddr` rule |
| The trusted address to a guest's SSH | Ports 2210 to 2212 of the gateway | Port 22 at the guest's own address |
| Anyone else to a guest's SSH | Dropped in the gateway's input chain | Dropped in the forward chain |

As well as IPv4 forwarding, the gateway needs:

- **IPv6 forwarding switched on**, with `net.ipv6.conf.all.forwarding = 1`. That stops Linux accepting router
  advertisements, so if the WAN interface gets its own IPv6 address or default route from them, also set
  `net.ipv6.conf.eth0.accept_ra = 2`.
- **The guests' network routed to it.** The provider (or the Proxmox host) has to route `2001:db8:0:1::/64` to the
  gateway's WAN address. A network that's only on the WAN link itself, rather than routed, doesn't reach the LAN.
- **The guests using it as their IPv6 gateway**, either set on each guest or advertised to them (e.g. with radvd).

## The same gateway, with its forwards in maps
The port forwards can instead go in named [maps](maps.md), with one rule for the public forwards (one per protocol), and
one for the SSH forwards. The trusted addresses go in a [named set](sets.md), so the SSH rule checks the source once,
however many forwards there are. A forward or trusted address can then be added or removed with `nft add element` and
`nft delete element`, without reloading the ruleset.

This carries on from the [IPv4 gateway](#a-nat-gateway-with-port-forwards), with the same variables and chains, and a
new ruleset:

```php
use Programster\Nftables\Collections\PortForwardCollection;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\PortForwardMapLayout;
use Programster\Nftables\NamedSet;
use Programster\Nftables\PortForward;

$trusted = NamedSet::createAddressSet($table, "trusted", IpVersion::IPV4, $trustedIp);
$public = new PortForwardCollection([new PortForward(80, $webProxy, 80), new PortForward(443, $webProxy, 443)]);
$publicUdp = new PortForwardCollection([new PortForward(443, $webProxy, 443)]);

$ssh = new PortForwardCollection([
    new PortForward(2210, $webProxy, 22),
    new PortForward(2211, $appServer, 22),
    new PortForward(2212, $database, 22),
]);

$ruleset = new Ruleset();

$ruleset->addRule(
    RuleFactory::createAcceptInterface($input, $loopback),
    RuleFactory::createAcceptInterface($input, $lan),
    RuleFactory::createAcceptInterface($input, $wan, $replies),
    RuleFactory::createAcceptPort($input, $wan, 22, sourceAddress: $trustedIp, comment: "SSH to the gateway"),

    RuleFactory::createForward($forward, $lan, $wan),
    RuleFactory::createForward($forward, $wan, $lan, $replies),
    RuleFactory::createMasquerade($postrouting, $wan),

    // Every port forward, in three rules: the public TCP forwards, the public UDP forwards (HTTP/3), and the SSH ones.
    RuleFactory::createMapPortForward($prerouting, $wan, "public", PortForwardMapLayout::TWO_MAPS, IpVersion::IPV4, $public),
    RuleFactory::createMapPortForward($prerouting, $wan, "public_udp", PortForwardMapLayout::TWO_MAPS, IpVersion::IPV4, $publicUdp, Protocol::UDP),
    RuleFactory::createMapPortForward($prerouting, $wan, "ssh", PortForwardMapLayout::TWO_MAPS, IpVersion::IPV4, $ssh, allowedSources: $trusted),
    RuleFactory::createAcceptPortForwards($forward),
);
```

```nft
set trusted {
	type ipv4_addr
	flags interval
	elements = { 198.51.100.7 }
}

map public_addresses {
	type inet_service : ipv4_addr
	elements = { 80 : 10.0.0.10,
		     443 : 10.0.0.10 }
}

map public_ports {
	type inet_service : inet_service
	elements = { 80 : 80,
		     443 : 443 }
}

map public_udp_addresses {
	type inet_service : ipv4_addr
	elements = { 443 : 10.0.0.10 }
}

map public_udp_ports {
	type inet_service : inet_service
	elements = { 443 : 443 }
}

map ssh_addresses {
	type inet_service : ipv4_addr
	elements = { 2210 : 10.0.0.10,
		     2211 : 10.0.0.11,
		     2212 : 10.0.0.12 }
}

map ssh_ports {
	type inet_service : inet_service
	elements = { 2210 : 22,
		     2211 : 22,
		     2212 : 22 }
}

chain prerouting {
	type nat hook prerouting priority dstnat; policy accept;
	iifname "eth0" dnat ip to tcp dport map @public_addresses:tcp dport map @public_ports
	iifname "eth0" dnat ip to udp dport map @public_udp_addresses:udp dport map @public_udp_ports
	iifname "eth0" ip saddr @trusted dnat ip to tcp dport map @ssh_addresses:tcp dport map @ssh_ports
}
```

The other chains are the same as before. With [IPv6 added](#taking-it-further-adding-ipv6), its IPv6 rules stay as they
are, as IPv6 is routed rather than port forwarded. To forward port 2213 to a new guest's SSH, without reloading:

```bash
nft add element inet gateway ssh_addresses '{ 2213 : 10.0.0.13 }'
nft add element inet gateway ssh_ports '{ 2213 : 22 }'
```

The next reload replaces the maps with what the ruleset says, so add the forward to the PHP as well. `TWO_MAPS` works
on every [target](targets.md). With a target of nft 1.1.3 (e.g. Debian 13) or RHEL 9, `ONE_MAP` keeps each forward's
address and port together in a single map. See [port forwarding from a map](rules.md#port-forwarding-from-a-map).

## A web server
A single server, on the internet at `eth0`, serving HTTP, HTTPS and HTTP/3 to anyone, and SSH only to your trusted
address. A [named set](sets.md) holds addresses to block, which can be changed without reloading:

```php
use Programster\Nftables\BaseChain;
use Programster\Nftables\ConnectionStateSet;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\MatchFactory;
use Programster\Nftables\NamedSet;
use Programster\Nftables\PortSet;
use Programster\Nftables\Rule;
use Programster\Nftables\RuleFactory;
use Programster\Nftables\Ruleset;
use Programster\Nftables\Table;

$loopback = "lo";
$wan = "eth0";
$trustedIp = "198.51.100.7";

$table = new Table("firewall", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::DROP);
$replies = new ConnectionStateSet(ConnectionState::ESTABLISHED, ConnectionState::RELATED);
$blocklist = NamedSet::createAddressSet($table, "blocklist", IpVersion::IPV4, "203.0.113.66", "192.0.2.0/24");
$fromBlocklist = MatchFactory::createInSet(PayloadExpression::create(PayloadField::IP_SADDR), $blocklist);

$ruleset = new Ruleset();

$ruleset->addRule(
    Rule::create($input, $fromBlocklist, Verdict::DROP)->withComment("blocked addresses"),
    RuleFactory::createAcceptInterface($input, $loopback),
    RuleFactory::createAcceptInterface($input, $wan, $replies),
    RuleFactory::createAcceptEssentialIcmpv6($input),
    RuleFactory::createAcceptPort($input, $wan, new PortSet(80, 443)),
    RuleFactory::createAcceptPort($input, $wan, 443, Protocol::UDP, comment: "HTTP/3"),
    RuleFactory::createAcceptPort($input, $wan, 22, sourceAddress: $trustedIp, comment: "SSH from the trusted address"),
);

file_put_contents("/etc/firewall/ruleset.json", $ruleset->toJson());
```

```nft
table inet firewall {
	set blocklist {
		type ipv4_addr
		flags interval
		elements = { 192.0.2.0/24, 203.0.113.66 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @blocklist drop comment "blocked addresses"
		iifname "lo" accept
		iifname "eth0" ct state established,related accept
		icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept
		iifname "eth0" tcp dport { 80, 443 } accept
		iifname "eth0" udp dport 443 accept comment "HTTP/3"
		iifname "eth0" tcp dport 22 ip saddr 198.51.100.7 accept comment "SSH from the trusted address"
	}
}
```

The blocklist rule comes first, so a blocked address can't use the rules after it, even for HTTP. To block another
address, or unblock one, without reloading:

```bash
nft add element inet firewall blocklist '{ 198.51.100.99 }'
nft delete element inet firewall blocklist '{ 203.0.113.66 }'
```

As with the maps, the next reload replaces the set with what the ruleset says.
