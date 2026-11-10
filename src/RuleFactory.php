<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\StatementCollection;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\FibFlag;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\RtKey;
use Programster\Nftables\Enums\TcpOptionField;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
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
     * Create a masquerade rule, which makes traffic leaving by an interface appear to come from this machine, e.g. so
     * machines behind it can reach the internet through its public address.
     *
     * @param BaseChain $postroutingChain - a nat chain on the postrouting hook.
     *
     * @param string $outputInterfaceName - the interface the traffic leaves by, typically the WAN interface.
     *
     * @param string $comment - optionally, a comment for the rule.
     *
     * @return Rule
     *
     * @throws UnsuitableChainException - if the chain isn't a nat chain on the postrouting hook.
     */
    public static function createMasquerade(
        BaseChain $postroutingChain,
        string $outputInterfaceName,
        string $comment = "",
    ) : Rule
    {
        ChainLib::assertChainIs($postroutingChain, ChainType::NAT, "masquerade", ChainHook::POSTROUTING);
        $statements = [MatchFactory::createOutputInterfaceName($outputInterfaceName), new MasqueradeStatement()];
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
