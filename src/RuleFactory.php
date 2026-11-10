<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\PortForwardCollection;
use Programster\Nftables\Collections\SetTypeCollection;
use Programster\Nftables\Collections\StatementCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\CtKey;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\FibFlag;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Enums\Icmpv6Type;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\PortForwardMapLayout;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\RtKey;
use Programster\Nftables\Enums\SetType;
use Programster\Nftables\Enums\TcpOptionField;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\Expressions\ConcatExpression;
use Programster\Nftables\Expressions\CtExpression;
use Programster\Nftables\Expressions\FibExpression;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Expressions\RtExpression;
use Programster\Nftables\Expressions\SetExpression;
use Programster\Nftables\Expressions\TcpOptionExpression;
use Programster\Nftables\Statements\DnatStatement;
use Programster\Nftables\Statements\FlowOffloadStatement;
use Programster\Nftables\Statements\MangleStatement;
use Programster\Nftables\Statements\MasqueradeStatement;
use Programster\Nftables\Statements\MatchStatement;

/**
 * Creates the rules a typical firewall or NAT gateway needs. Each one checks it's being added to a suitable chain, and
 * ends with a verdict, so it always does something. For anything else, create a Rule directly.
 */
final class RuleFactory
{
    private function __construct()
    {
    }


    /**
     * Create a rule that accepts everything arriving on an interface, e.g. "lo" for the loopback interface, or a
     * trusted LAN interface.
     *
     * @param BaseChain $inputChain - a filter chain on the input hook.
     *
     * @param string $interfaceName - the interface's name.
     *
     * @param ConnectionStateSet|null $states - optionally, only accept connections in these states, e.g. established
     * and related, for traffic arriving on a WAN interface in reply to connections this machine made. Defaults to
     * null, for any state.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the input hook.
     */
    public static function createAcceptInterface(
        BaseChain $inputChain,
        string $interfaceName,
        ?ConnectionStateSet $states = null,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($inputChain, ChainType::FILTER, "accept an interface's traffic", ChainHook::INPUT);
        $statements = [MatchFactory::createInputInterfaceName($interfaceName)];

        if ($states !== null)
        {
            $statements[] = MatchFactory::createConnectionStates($states);
        }

        $statements[] = Verdict::ACCEPT;
        return Rule::create($inputChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a rule that accepts traffic to a port (or ports) on this machine, optionally only from somewhere in
     * particular, e.g. to open port 443 for a web server.
     *
     * @param BaseChain $inputChain - a filter chain on the input hook.
     *
     * @param string $interfaceName - the interface the traffic must arrive on.
     *
     * @param int|PortSet|PortRange $ports - the port, ports or range of ports to accept.
     *
     * @param Protocol $protocol - the transport protocol. Defaults to TCP.
     *
     * @param string|null $destinationAddress - optionally, the IP address or network CIDR the traffic must be going
     * to, for a machine with more than one address. Defaults to null, for any.
     *
     * @param string|null $sourceAddress - optionally, the IP address or network CIDR the traffic must come from.
     * Defaults to null, for anywhere.
     *
     * @param ConnectionStateSet|null $states - optionally, only accept connections in these states. Defaults to null,
     * for any state.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the input hook.
     * @throws InvalidAddressException - if an address isn't an IP address or network CIDR.
     * @throws BadArgumentException - if a port isn't between 1 and 65535.
     */
    public static function createAcceptPort(
        BaseChain $inputChain,
        string $interfaceName,
        int|PortSet|PortRange $ports,
        Protocol $protocol = Protocol::TCP,
        ?string $destinationAddress = null,
        ?string $sourceAddress = null,
        ?ConnectionStateSet $states = null,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($inputChain, ChainType::FILTER, "accept a port", ChainHook::INPUT);

        $statements = [
            MatchFactory::createInputInterfaceName($interfaceName),
            MatchFactory::createDestinationPorts($protocol, $ports),
            ...self::createAddressMatches($sourceAddress, $destinationAddress)->toArray(),
        ];

        if ($states !== null)
        {
            $statements[] = MatchFactory::createConnectionStates($states);
        }

        $statements[] = Verdict::ACCEPT;
        return Rule::create($inputChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a rule that port forwards: it changes the destination of traffic arriving on a port (or range of ports)
     * to another machine, typically one behind this one. This only translates the address. Unless the forward chain's
     * policy is accept, the forwarded traffic also needs accepting there (see createForward()).
     *
     * @param BaseChain $preroutingChain - a nat chain on the prerouting hook.
     *
     * @param string $inputInterfaceName - the interface the traffic arrives on, typically the WAN interface.
     *
     * @param int|PortRange $incomingPorts - the port, or range of ports, the traffic arrives on.
     *
     * @param string $newDestinationAddress - the IP address to send it to.
     *
     * @param int|PortRange|null $newDestinationPorts - the port to send it to. Defaults to null, which keeps each
     * packet's port, and is the only option for a range other than the same range (nftables doesn't map one range of
     * ports onto a different range one to one).
     *
     * @param Protocol $protocol - the transport protocol. Defaults to TCP.
     *
     * @param string|null $sourceAddress - optionally, the IP address or network CIDR the traffic must come from.
     * Defaults to null, for anywhere.
     *
     * @param string|null $destinationAddress - optionally, the IP address or network CIDR the traffic must have been
     * sent to (not to be confused with $newDestinationAddress). Defaults to null, for any.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a nat chain on the prerouting hook.
     * @throws InvalidAddressException - if an address isn't an IP address or network CIDR.
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535, or the ports can't be mapped (a range to a
     * different range, or a single port to a range).
     */
    public static function createPortForward(
        BaseChain $preroutingChain,
        string $inputInterfaceName,
        int|PortRange $incomingPorts,
        string $newDestinationAddress,
        int|PortRange|null $newDestinationPorts = null,
        Protocol $protocol = Protocol::TCP,
        ?string $sourceAddress = null,
        ?string $destinationAddress = null,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($preroutingChain, ChainType::NAT, "port forward", ChainHook::PREROUTING);

        if ($newDestinationPorts instanceof PortRange)
        {
            $isSameRange = ($incomingPorts instanceof PortRange && $incomingPorts->equals($newDestinationPorts));

            if (!$isSameRange)
            {
                $message = "Ports can only be forwarded to the same range. Pass null to keep each packet's port.";
                throw new BadArgumentException($message);
            }
        }

        $statements = [
            MatchFactory::createInputInterfaceName($inputInterfaceName),
            MatchFactory::createDestinationPorts($protocol, $incomingPorts),
            ...self::createAddressMatches($sourceAddress, $destinationAddress)->toArray(),
            DnatStatement::create($newDestinationAddress, $newDestinationPorts),
        ];

        return Rule::create($preroutingChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a rule that does many port forwards at once, from a named map of incoming ports, rather than a rule per
     * forward (see docs/maps.md). The forwards can be changed at runtime with "nft add element", without reloading the
     * rules. Traffic to a port that isn't in the map isn't forwarded, and carries on to this machine's input chain. As
     * with createPortForward(), the forwarded traffic also needs accepting in the forward chain, unless its policy is
     * accept.
     *
     * @param BaseChain $preroutingChain - a nat chain on the prerouting hook, in a table of the forwards' IP version
     * (or an inet table).
     *
     * @param string $inputInterfaceName - the interface the traffic arrives on, typically the WAN interface.
     *
     * @param string $mapName - the name of the map, or the start of the two maps' names (see $layout). It must be
     * unique among the sets and maps in the table.
     *
     * @param PortForwardMapLayout $layout - one map (needs nft 1.1.3, or RHEL 9) or two (works everywhere). There's no
     * default, as it depends on the target the ruleset is for.
     *
     * @param IpVersion $ipVersion - the IP version of the addresses forwarded to.
     *
     * @param PortForwardCollection $forwards - the forwards. It can be empty, for forwards that are only added at
     * runtime.
     *
     * @param Protocol $protocol - the transport protocol. Defaults to TCP. A UDP forward needs a rule (and map) of its
     * own.
     *
     * @param NamedSet|null $allowedSources - optionally, a set of the addresses (or networks) the traffic must come
     * from, e.g. an allowlist for SSH. Defaults to null, for anywhere.
     *
     * @param string|null $destinationAddress - optionally, the IP address or network CIDR the traffic must have been
     * sent to, for a machine with more than one address. Defaults to null, for any.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a nat chain on the prerouting hook, or its table is for the
     * other IP version, or the allowed sources set is in another table.
     *
     * @throws BadArgumentException - if a forward is for the other IP version, two forwards share an incoming port, or
     * the map's name is empty or too long.
     *
     * @throws InvalidAddressException - if $destinationAddress isn't an IP address or network CIDR.
     */
    public static function createMapPortForward(
        BaseChain $preroutingChain,
        string $inputInterfaceName,
        string $mapName,
        PortForwardMapLayout $layout,
        IpVersion $ipVersion,
        PortForwardCollection $forwards,
        Protocol $protocol = Protocol::TCP,
        ?NamedSet $allowedSources = null,
        ?string $destinationAddress = null,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($preroutingChain, ChainType::NAT, "port forward", ChainHook::PREROUTING);
        $table = $preroutingChain->getTable();
        $family = $table->getFamily();
        $suitableFamily = ($ipVersion === IpVersion::IPV4) ? Family::IP : Family::IP6;

        if ($family !== $suitableFamily && $family !== Family::INET)
        {
            $needs = "an {$suitableFamily->value} or inet table";
            $message = "A port forward to {$ipVersion->name} addresses needs {$needs}, not {$family->value}.";
            throw new UnsuitableChainException($message);
        }

        $incomingPorts = [];
        $addresses = [];
        $ports = [];
        $concatenations = [];

        foreach ($forwards as $forward)
        {
            $incomingPort = $forward->getIncomingPort();

            if ($forward->getIpVersion() !== $ipVersion)
            {
                $message = "The port forward from port {$incomingPort} isn't to an {$ipVersion->name} address.";
                throw new BadArgumentException($message);
            }

            if (isset($incomingPorts[$incomingPort]))
            {
                throw new BadArgumentException("Port {$incomingPort} is forwarded more than once.");
            }

            $incomingPorts[$incomingPort] = true;
            $addresses[] = new MapElement($incomingPort, $forward->getAddress());
            $ports[] = new MapElement($incomingPort, $forward->getPort());
            $concatenation = new ConcatExpression($forward->getAddress(), $forward->getPort());
            $concatenations[] = new MapElement($incomingPort, $concatenation);
        }

        $addressType = ($ipVersion === IpVersion::IPV4) ? SetType::IPV4_ADDR : SetType::IPV6_ADDR;
        $incomingPort = PayloadExpression::create(PayloadField::from("{$protocol->value} dport"));

        if ($layout === PortForwardMapLayout::ONE_MAP)
        {
            $addressAndPort = new SetTypeCollection([$addressType, SetType::INET_SERVICE]);
            $map = NamedMap::create($table, $mapName, SetType::INET_SERVICE, $addressAndPort);
            $map = $map->withElements(...$concatenations);
            $dnat = DnatStatement::createFromMap($ipVersion, $map->lookUp($incomingPort));
        }
        else
        {
            $addressMap = NamedMap::create($table, "{$mapName}_addresses", SetType::INET_SERVICE, $addressType);
            $addressMap = $addressMap->withElements(...$addresses);
            $portMap = NamedMap::create($table, "{$mapName}_ports", SetType::INET_SERVICE, SetType::INET_SERVICE);
            $portMap = $portMap->withElements(...$ports);
            $toAddress = $addressMap->lookUp($incomingPort);
            $dnat = DnatStatement::createFromMap($ipVersion, $toAddress, $portMap->lookUp($incomingPort));
        }

        $statements = [MatchFactory::createInputInterfaceName($inputInterfaceName)];

        if ($allowedSources !== null)
        {
            $sourceField = ($ipVersion === IpVersion::IPV4) ? PayloadField::IP_SADDR : PayloadField::IP6_SADDR;
            $statements[] = MatchFactory::createInSet(PayloadExpression::create($sourceField), $allowedSources);
        }

        if ($destinationAddress !== null)
        {
            $statements[] = MatchFactory::createDestinationAddress($destinationAddress);
        }

        $statements[] = $dnat;
        return Rule::create($preroutingChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a rule that accepts traffic being forwarded through this machine from one interface to another, e.g. the
     * traffic a port forward sends on to a machine behind this one, or the replies to it.
     *
     * @param BaseChain $forwardChain - a filter chain on the forward hook.
     *
     * @param string $inputInterfaceName - the interface the traffic must arrive on.
     *
     * @param string $outputInterfaceName - the interface the traffic must be leaving by.
     *
     * @param ConnectionStateSet|null $states - optionally, only accept connections in these states, e.g. new for
     * connections being started, or established and related for their replies. Defaults to null, for any state.
     *
     * @param Protocol $protocol - the transport protocol, which only matters with $destinationPorts or
     * $requireTcpSyn. Defaults to TCP.
     *
     * @param int|PortSet|PortRange|null $destinationPorts - optionally, the port(s) the traffic must be going to.
     * Defaults to null, for any.
     *
     * @param string|null $sourceAddress - optionally, the IP address or network CIDR the traffic must come from.
     * Defaults to null, for anywhere.
     *
     * @param string|null $destinationAddress - optionally, the IP address or network CIDR the traffic must be going
     * to. Defaults to null, for anywhere.
     *
     * @param bool $requireTcpSyn - whether to only accept TCP packets that start a connection properly (see
     * MatchFactory::createTcpSyn()), for use with the new state. Defaults to false.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the forward hook.
     * @throws InvalidAddressException - if an address isn't an IP address or network CIDR.
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535, or $requireTcpSyn is given with a protocol
     * other than TCP.
     */
    public static function createForward(
        BaseChain $forwardChain,
        string $inputInterfaceName,
        string $outputInterfaceName,
        ?ConnectionStateSet $states = null,
        Protocol $protocol = Protocol::TCP,
        int|PortSet|PortRange|null $destinationPorts = null,
        ?string $sourceAddress = null,
        ?string $destinationAddress = null,
        bool $requireTcpSyn = false,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($forwardChain, ChainType::FILTER, "accept forwarded traffic", ChainHook::FORWARD);

        if ($requireTcpSyn && $protocol !== Protocol::TCP)
        {
            throw new BadArgumentException("Only TCP has a SYN flag to check.");
        }

        $statements = [
            MatchFactory::createInputInterfaceName($inputInterfaceName),
            MatchFactory::createOutputInterfaceName($outputInterfaceName),
            ...self::createAddressMatches($sourceAddress, $destinationAddress)->toArray(),
        ];

        if ($destinationPorts !== null)
        {
            $statements[] = MatchFactory::createDestinationPorts($protocol, $destinationPorts);
        }

        if ($states !== null)
        {
            $statements[] = MatchFactory::createConnectionStates($states);
        }

        if ($requireTcpSyn)
        {
            $statements[] = MatchFactory::createTcpSyn();
        }

        $statements[] = Verdict::ACCEPT;
        return Rule::create($forwardChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a rule that accepts every connection that was port forwarded (ct status dnat), in either direction, e.g.
     * after createMapPortForward(), so the forwards don't each need a rule in the forward chain too. A connection is
     * only port forwarded if a rule in a nat chain chose to, so this doesn't open anything else.
     *
     * @param BaseChain $forwardChain - a filter chain on the forward hook.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the forward hook.
     */
    public static function createAcceptPortForwards(BaseChain $forwardChain, string $comment = "") : Rule
    {
        ChainLib::assertChainIs($forwardChain, ChainType::FILTER, "accept port forwards", ChainHook::FORWARD);
        $wasPortForwarded = new MatchStatement(new CtExpression(CtKey::STATUS), Operator::IN, "dnat");
        return Rule::create($forwardChain, $wasPortForwarded, Verdict::ACCEPT)->withComment($comment);
    }


    /**
     * Create a rule that accepts the ICMPv6 messages IPv6 can't work without, which RFC 4890 says a firewall mustn't
     * drop. Unlike ICMP for IPv4, these aren't optional: without neighbour discovery (IPv6's ARP), a machine can't
     * reach its neighbours or its router, and without packet too big errors, connections over a route with a smaller
     * MTU hang. Put one in each chain with a drop policy that IPv6 passes through:
     *
     * - in an input chain: errors (destination unreachable, packet too big, time exceeded and parameter problem),
     * neighbour and router discovery, and multicast listener discovery.
     *
     * - in a forward chain: errors only, as discovery never crosses a router.
     *
     * Pings aren't included. To accept those too, add a rule with MatchFactory::createIcmpv6Types().
     *
     * @param BaseChain $chain - a filter chain on the input or forward hook, in an ip6 or inet table.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the input or forward hook, in an ip6 or
     * inet table.
     */
    public static function createAcceptEssentialIcmpv6(BaseChain $chain, string $comment = "") : Rule
    {
        $purpose = "accept essential ICMPv6";
        ChainLib::assertChainIs($chain, ChainType::FILTER, $purpose, ChainHook::INPUT, ChainHook::FORWARD);
        $family = $chain->getTable()->getFamily();

        if ($family !== Family::IP6 && $family !== Family::INET)
        {
            $message = "A rule to {$purpose} needs an ip6 or inet table, not {$family->value}.";
            throw new UnsuitableChainException($message);
        }

        $types = [
            Icmpv6Type::DESTINATION_UNREACHABLE,
            Icmpv6Type::PACKET_TOO_BIG,
            Icmpv6Type::TIME_EXCEEDED,
            Icmpv6Type::PARAMETER_PROBLEM,
        ];

        if ($chain->getHook() === ChainHook::INPUT)
        {
            $types[] = Icmpv6Type::ND_ROUTER_SOLICIT;
            $types[] = Icmpv6Type::ND_ROUTER_ADVERT;
            $types[] = Icmpv6Type::ND_NEIGHBOR_SOLICIT;
            $types[] = Icmpv6Type::ND_NEIGHBOR_ADVERT;
            $types[] = Icmpv6Type::MLD_LISTENER_QUERY;
            $types[] = Icmpv6Type::MLD_LISTENER_REPORT;
            $types[] = Icmpv6Type::MLD_LISTENER_DONE;
            $types[] = Icmpv6Type::MLD2_LISTENER_REPORT;
        }

        $isEssential = MatchFactory::createIcmpv6Types(...$types);
        return Rule::create($chain, $isEssential, Verdict::ACCEPT)->withComment($comment);
    }


    /**
     * Create a masquerade rule, which makes traffic leaving by an interface appear to come from this machine, e.g. so
     * machines behind it can reach the internet through its public address.
     *
     * @param BaseChain $postroutingChain - a nat chain on the postrouting hook.
     *
     * @param string $outputInterfaceName - the interface the traffic leaves by, typically the WAN interface.
     *
     * @param IpVersion|null $ipVersion - optionally, only masquerade this IP version (meta nfproto ipv4), e.g. IPv4 in
     * an inet table, for machines behind this one that have public IPv6 addresses of their own, so their IPv6 traffic
     * is routed rather than NATed. Defaults to null, for whichever versions the chain's table handles.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a nat chain on the postrouting hook, or $ipVersion is the
     * other version to its ip or ip6 table's.
     */
    public static function createMasquerade(
        BaseChain $postroutingChain,
        string $outputInterfaceName,
        ?IpVersion $ipVersion = null,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($postroutingChain, ChainType::NAT, "masquerade", ChainHook::POSTROUTING);
        $family = $postroutingChain->getTable()->getFamily();
        $statements = [MatchFactory::createOutputInterfaceName($outputInterfaceName)];

        if ($ipVersion !== null && $family === Family::INET)
        {
            $nfproto = ($ipVersion === IpVersion::IPV4) ? "ipv4" : "ipv6";
            $statements[] = new MatchStatement(new MetaExpression(MetaKey::NFPROTO), Operator::EQUALS, $nfproto);
        }
        elseif ($ipVersion !== null && $family->value !== $ipVersion->value)
        {
            $message = "A {$family->value} table only handles one IP version, so it can't masquerade the other.";
            throw new UnsuitableChainException($message);
        }

        $statements[] = new MasqueradeStatement();
        return Rule::create($postroutingChain, ...$statements)->withComment($comment);
    }


    /**
     * Create a reverse path filter, which drops packets that couldn't have arrived on the interface they did: those
     * whose source address this machine wouldn't route back out of that interface (fib saddr . iif oif missing). That's
     * how packets with spoofed source addresses are spotted. It's best early on, in a chain with a low priority.
     *
     * @param BaseChain $preroutingChain - a filter chain on the prerouting hook, in an ip, ip6 or inet table.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the prerouting hook, in an ip, ip6 or
     * inet table.
     */
    public static function createReversePathFilter(BaseChain $preroutingChain, string $comment = "") : Rule
    {
        ChainLib::assertChainIs($preroutingChain, ChainType::FILTER, "filter by reverse path", ChainHook::PREROUTING);
        ChainLib::assertIpFamily($preroutingChain, "filter by reverse path");
        $route = new FibExpression(FibResult::OIF, FibFlag::SADDR, FibFlag::IIF);
        $hasNoRoute = MatchFactory::createExistence($route, Existence::MISSING);
        return Rule::create($preroutingChain, $hasNoRoute, Verdict::DROP)->withComment($comment);
    }


    /**
     * Create an MSS clamping rule, which lowers the maximum segment size that TCP connections passing through this
     * machine ask for, to fit the MTU of their route (tcp option maxseg size set rt mtu). Without it, connections
     * through a link with a smaller MTU than usual (e.g. a VPN, or PPPoE) can hang once they send a full sized packet.
     *
     * @param BaseChain $forwardChain - a filter chain on the forward hook, in an ip, ip6 or inet table.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the forward hook, in an ip, ip6 or inet
     * table.
     */
    public static function createMssClamp(BaseChain $forwardChain, string $comment = "") : Rule
    {
        ChainLib::assertChainIs($forwardChain, ChainType::FILTER, "clamp the MSS", ChainHook::FORWARD);
        ChainLib::assertIpFamily($forwardChain, "clamp the MSS");
        $isSyn = new MatchStatement(PayloadExpression::create(PayloadField::TCP_FLAGS), Operator::IN, "syn");
        $maximumSegmentSize = TcpOptionExpression::createField(TcpOptionField::MAXSEG_SIZE);
        $clamp = new MangleStatement($maximumSegmentSize, new RtExpression(RtKey::MTU));
        return Rule::create($forwardChain, $isSyn, $clamp)->withComment($comment);
    }


    /**
     * Create a rule that offloads forwarded TCP and UDP connections to a flowtable, so the rest of their packets skip
     * the network stack (meta l4proto { tcp, udp } flow add @fastpath). See Flowtable for what that changes. Put it
     * near the start of the forward chain, after any rules that drop traffic, as offloaded connections don't see the
     * chain's later rules.
     *
     * @param BaseChain $forwardChain - a filter chain on the forward hook, in the flowtable's table.
     *
     * @param Flowtable $flowtable - the flowtable.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a filter chain on the forward hook, in the flowtable's
     * table.
     */
    public static function createFlowOffload(BaseChain $forwardChain, Flowtable $flowtable, string $comment = "") : Rule
    {
        $l4proto = new MetaExpression(MetaKey::L4PROTO);
        $isTcpOrUdp = new MatchStatement($l4proto, Operator::EQUALS, new SetExpression("tcp", "udp"));
        $offload = new FlowOffloadStatement($flowtable);
        return Rule::create($forwardChain, $isTcpOrUdp, $offload)->withComment($comment);
    }


    /**
     * Create the optional source and destination address matches that several rules take.
     *
     * @param string|null $sourceAddress - the source IP address or network CIDR, or null for none.
     *
     * @param string|null $destinationAddress - the destination IP address or network CIDR, or null for none.
     *
     * @return StatementCollection - the matches.
     *
     * @throws InvalidAddressException - if an address isn't an IP address or network CIDR.
     */
    private static function createAddressMatches(
        ?string $sourceAddress,
        ?string $destinationAddress,
    ) : StatementCollection
    {
        $matches = new StatementCollection();

        if ($sourceAddress !== null)
        {
            $matches->add(MatchFactory::createSourceAddress($sourceAddress));
        }

        if ($destinationAddress !== null)
        {
            $matches->add(MatchFactory::createDestinationAddress($destinationAddress));
        }

        return $matches;
    }
}
