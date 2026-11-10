# Named objects

- [Using a named object](#using-a-named-object)
- [Counters, quotas and limits](#counters-quotas-and-limits)
- [Conntrack helpers](#conntrack-helpers)
- [Conntrack timeouts](#conntrack-timeouts)
- [Conntrack expectations](#conntrack-expectations)
- [Synproxies](#synproxies)
- [Security marks](#security-marks)

A named object is something with state, e.g. a counter, that lives in a table alongside its chains, so any number of
rules can share it, and `nft list` can show (or reset) its state. They're all in the `Programster\Nftables\Objects`
namespace. The examples leave out `use` statements. Every other class is in `Programster\Nftables`, or one of its
`Enums`, `Statements`, `Expressions` and `Exceptions` namespaces.

```php
$table = new Table("gateway", Family::INET);
$input = new BaseChain("input", $table, ChainType::FILTER, ChainHook::INPUT, Priority::FILTER, Policy::ACCEPT);
$forward = new BaseChain("forward", $table, ChainType::FILTER, ChainHook::FORWARD, Priority::FILTER, Policy::ACCEPT);
$ruleset = new Ruleset();
```

## Using a named object
Each object's `createStatement()` gives the statement that uses it for a packet, e.g. counts it, for a counter. Adding
a rule with one adds the object to the ruleset too, and `Ruleset::addObject()` adds one that no rule uses. Each kind
of object has names of its own, so a counter and a quota can both be called `guest1`.

Reloading the ruleset recreates its objects, so their state (e.g. a counter's count) starts again.

## Counters, quotas and limits
A `NamedCounter` counts the packets and bytes of every rule that uses it, e.g. to total a guest's traffic in both
directions. A `NamedQuota` and a `NamedLimit` take a [QuotaStatement](statements.md#quotas) or
[LimitStatement](statements.md#rate-limits) for their settings, and are shared the same way:

```php
$guest1 = new NamedCounter("guest1", $table);
$guest1Quota = new NamedQuota("guest1", $table, new QuotaStatement(10240, QuotaUnit::MBYTES, QuotaMatch::OVER_QUOTA));
$fromGuest1 = MatchFactory::createSourceAddress("10.0.0.2");
$toGuest1 = MatchFactory::createDestinationAddress("10.0.0.2");

$ruleset->addRule(Rule::create($forward, $fromGuest1, $guest1->createStatement(), $guest1Quota->createStatement(), Verdict::DROP));
$ruleset->addRule(Rule::create($forward, $toGuest1, $guest1->createStatement(), $guest1Quota->createStatement(), Verdict::DROP));
```

```nft
counter guest1 {
	packets 0 bytes 0
}

quota guest1 {
	over 10240 mbytes
}

ip saddr 10.0.0.2 counter name "guest1" quota name "guest1" drop
ip daddr 10.0.0.2 counter name "guest1" quota name "guest1" drop
```

Both rules count towards the same counter, and once the guest has used 10 GB in total, either way, the quota matches
and the rest of its traffic is dropped. A statement that doesn't match ends the rule, so until then, its packets
carry on to the next rule. To read the count and start it again:

```bash
nft list counter inet gateway guest1
nft reset quota inet gateway guest1
```

## Conntrack helpers
Some protocols open further connections, e.g. FTP's data connections, on ports that are only agreed inside the first
connection. A `CtHelper` understands one of those protocols (a `CtHelperType`). Once a rule gives a connection the
helper, the kernel reads the connection, recognises the connections it opens as `related`, and NATs them to match:

```php
$prerouting = new BaseChain("helpers", $table, ChainType::FILTER, ChainHook::PREROUTING, Priority::FILTER, Policy::ACCEPT);
$ftp = new CtHelper("ftp", $table, CtHelperType::FTP);
$toFtpServer = MatchFactory::createDestinationAddress("10.0.0.3");
$ruleset->addRule(Rule::create($prerouting, $toFtpServer, MatchFactory::createDestinationPorts(Protocol::TCP, 21), $ftp->createStatement()));
```

```nft
ct helper ftp {
	type "ftp" protocol tcp
	l3proto inet
}

ip daddr 10.0.0.3 tcp dport 21 ct helper set "ftp"
```

- The kernel doesn't give connections helpers by itself any more, and helpers have been the target of attacks, so only
  give one to the connections that need it, e.g. those to the FTP server's port.
- The rule must run after conntrack, i.e. in a chain with a priority above -200 (`Priority::FILTER` is 0).
- The `related` connections still need accepting, e.g. with a `ct state established,related accept` rule.
- Each helper needs its kernel module (e.g. `nf_conntrack_ftp`), which the kernel loads when the ruleset is loaded,
  if it can.
- Connections with a helper aren't offloaded to a [flowtable](flowtables.md).

## Conntrack timeouts
A `CtTimeout` sets how long conntrack keeps the connections given it in each state, in place of the system's defaults
(the `net.netfilter.nf_conntrack_*_timeout` sysctls). Each `CtTimeoutPolicy` is a `CtTimeoutState` (TCP or UDP) and a
number of seconds. E.g. to keep idle SSH connections for 2 hours, without changing the timeout for everything else:

```php
$raw = new BaseChain("raw", $table, ChainType::FILTER, ChainHook::PREROUTING, Priority::RAW, Policy::ACCEPT);
$longSsh = new CtTimeout("long_ssh", $table, new CtTimeoutPolicy(CtTimeoutState::TCP_ESTABLISHED, 7200));

$ruleset = new Ruleset(NftablesTarget::UBUNTU_24_04);
$ruleset->addRule(Rule::create($raw, MatchFactory::createDestinationPorts(Protocol::TCP, 22), $longSsh->createStatement()));
```

```nft
ct timeout long_ssh {
	protocol tcp
	l3proto inet
	policy = { established : 2h }
}

tcp dport 22 ct timeout set "long_ssh"
```

- It needs nft 1.0.9 (e.g. Ubuntu 24.04 or RHEL 9), as older nft crashes on one, or silently drops its timeouts.
- The rule must run before conntrack sees the connection's first packet, i.e. in a chain with a priority below -200
  (`Priority::RAW` is -300).
- A timeout's states must all be for one protocol, and each only once.
- nft's listing leaves out any timeout that's the same as the kernel's default.

## Conntrack expectations
A `CtExpectation` is a simpler stand-in for a [conntrack helper](#conntrack-helpers), for a protocol that always opens
its second connection on a known port. Once a rule gives a connection the expectation, conntrack expects a connection
back the other way, from the machine that was contacted to the one that contacted it, on that port, within a time, and
treats it as `related` to the first. The second
connection can then be accepted with `ct state related`, rather than opening its port to everyone.

It takes the IP version, the expected connection's protocol and port, how many seconds to wait for it, and how many
expected connections each connection can have waiting at once (from 1 to 255). E.g. for a service that's contacted on
port 5060, and replies by opening a connection back to port 5061:

```php
$callback = new CtExpectation("callback", $table, IpVersion::IPV4, Protocol::TCP, 5061, 60, 4);
$ruleset->addRule(Rule::create($input, MatchFactory::createDestinationPorts(Protocol::TCP, 5060), $callback->createStatement()));
```

```nft
ct expectation callback {
	protocol tcp
	dport 5061
	timeout 1m
	size 4
	l3proto ip
}

tcp dport 5060 ct expectation set "callback"
```

It needs nft 1.0.9 (e.g. Ubuntu 24.04 or RHEL 9), as older nft can't read one from JSON, and kernel 5.3.

## Synproxies
A `NamedSynproxy` is a [synproxy](statements.md#synproxy) whose settings several rules share. It needs nft 1.1.3 (or
RHEL 9), as older nft can't read one from JSON:

```php
$web = new NamedSynproxy("web", $table, new SynproxyStatement(1460, 7, SynproxyFlag::TIMESTAMP, SynproxyFlag::SACK_PERMITTED));
$untracked = MatchFactory::createConnectionStates(new ConnectionStateSet(ConnectionState::INVALID, ConnectionState::UNTRACKED));

$ruleset = new Ruleset(NftablesTarget::DEBIAN_13);
$ruleset->addRule(Rule::create($input, MatchFactory::createDestinationPorts(Protocol::TCP, 443), $untracked, $web->createStatement()));
```

```nft
synproxy web {
	mss 1460
	wscale 7
	timestamp sack-perm
}

tcp dport 443 ct state invalid,untracked synproxy name "web"
```

## Security marks
A `Secmark` gives packets a security context (`meta secmark set "ssh"`), so the security module's policy (e.g.
SELinux) can decide which programs may send and receive them. Loading it fails unless the security module knows the
context, and using one in a rule needs nft 1.0.6 (e.g. Debian 12):

```php
$secmarkRuleset = new Ruleset(NftablesTarget::DEBIAN_12);
$sshPacket = new Secmark("ssh", $table, "system_u:object_r:ssh_server_packet_t:s0");
$secmarkRuleset->addRule(Rule::create($input, MatchFactory::createDestinationPorts(Protocol::TCP, 22), $sshPacket->createStatement()));
```
