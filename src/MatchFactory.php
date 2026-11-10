<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\BinaryOperator;
use Programster\Nftables\Enums\Existence;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Enums\Icmpv6Type;
use Programster\Nftables\Enums\MatchMode;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Enums\PacketEndpoint;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Enums\CtKey;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Expressions\BinaryOperationExpression;
use Programster\Nftables\Expressions\CtExpression;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExthdrExpression;
use Programster\Nftables\Expressions\FibExpression;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\Expressions\PayloadExpression;
use Programster\Nftables\Expressions\PrefixExpression;
use Programster\Nftables\Expressions\SctpChunkExpression;
use Programster\Nftables\Expressions\SetExpression;
use Programster\Nftables\Expressions\TcpOptionExpression;
use Programster\Nftables\Statements\MatchStatement;

/**
 * Creates the common MatchStatements. For anything else, create a MatchStatement directly.
 */
final class MatchFactory
{
    private function __construct()
    {
    }


    /**
     * Match the interface a packet arrived on, by name (iifname), e.g. "lo" or "eth0".
     *
     * @param string $interfaceName - the interface's name.
     *
     * @param MatchMode $mode - whether to match packets that did, or didn't, arrive on it. Defaults to did.
     *
     * @return MatchStatement
     */
    public static function createInputInterfaceName(
        string $interfaceName,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return new MatchStatement(new MetaExpression(MetaKey::IIFNAME), $mode->getOperator(), $interfaceName);
    }


    /**
     * Match the interface a packet is leaving by, by name (oifname), e.g. "eth0".
     *
     * @param string $interfaceName - the interface's name.
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, leaving by it. Defaults to are.
     *
     * @return MatchStatement
     */
    public static function createOutputInterfaceName(
        string $interfaceName,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return new MatchStatement(new MetaExpression(MetaKey::OIFNAME), $mode->getOperator(), $interfaceName);
    }


    /**
     * Match a packet's destination port.
     *
     * @param Protocol $protocol - the transport protocol, e.g. TCP.
     *
     * @param int|PortSet|PortRange $ports - the port, ports or range of ports to match.
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, to them. Defaults to are.
     *
     * @return MatchStatement
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535.
     */
    public static function createDestinationPorts(
        Protocol $protocol,
        int|PortSet|PortRange $ports,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return self::createPortMatch($protocol, PacketEndpoint::DESTINATION, $ports, $mode);
    }


    /**
     * Match a packet's source port.
     *
     * @param Protocol $protocol - the transport protocol, e.g. TCP.
     *
     * @param int|PortSet|PortRange $ports - the port, ports or range of ports to match.
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, from them. Defaults to are.
     *
     * @return MatchStatement
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535.
     */
    public static function createSourcePorts(
        Protocol $protocol,
        int|PortSet|PortRange $ports,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return self::createPortMatch($protocol, PacketEndpoint::SOURCE, $ports, $mode);
    }


    /**
     * Match where a packet came from: a single IP address, or a network. IPv4 and IPv6 are both supported, and which
     * one is worked out from the address.
     *
     * @param string $addressOrCidr - an IP address (e.g. 10.0.0.1) or a network CIDR (e.g. 10.0.0.0/8).
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, from it. Defaults to are.
     *
     * @return MatchStatement
     *
     * @throws InvalidAddressException - if it isn't an IP address or network CIDR.
     */
    public static function createSourceAddress(
        string $addressOrCidr,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return self::createAddressMatch($addressOrCidr, PacketEndpoint::SOURCE, $mode);
    }


    /**
     * Match where a packet is going: a single IP address, or a network. IPv4 and IPv6 are both supported, and which
     * one is worked out from the address.
     *
     * @param string $addressOrCidr - an IP address (e.g. 10.0.0.1) or a network CIDR (e.g. 10.0.0.0/8).
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, going to it. Defaults to are.
     *
     * @return MatchStatement
     *
     * @throws InvalidAddressException - if it isn't an IP address or network CIDR.
     */
    public static function createDestinationAddress(
        string $addressOrCidr,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return self::createAddressMatch($addressOrCidr, PacketEndpoint::DESTINATION, $mode);
    }


    /**
     * Match part of a packet against a named set, e.g. its source address against a blocklist.
     *
     * @param Expression $left - what to look up in the set, e.g. PayloadExpression::create(PayloadField::IP_SADDR).
     *
     * @param NamedSet $set - the set.
     *
     * @param MatchMode $mode - whether to match packets that are, or aren't, in it. Defaults to are.
     *
     * @return MatchStatement
     */
    public static function createInSet(
        Expression $left,
        NamedSet $set,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return new MatchStatement($left, $mode->getOperator(), $set->getReference());
    }


    /**
     * Match whether a packet has something, e.g. an IPv6 fragment header (exthdr frag exists), or whether a fib lookup
     * found a route (fib saddr . iif oif missing, which spots spoofed packets).
     *
     * @param FibExpression|ExthdrExpression|TcpOptionExpression|SctpChunkExpression $left - what to check for: a whole
     * IPv6 extension header, TCP option or SCTP chunk (not one of its fields), or a fib lookup of an interface
     * (FibResult::OIF or OIFNAME).
     *
     * @param Existence $existence - whether to match packets that have it, or don't.
     *
     * @return MatchStatement
     *
     * @throws BadArgumentException - if $left is a field, or a fib lookup of an address type, which can't be checked
     * for.
     */
    public static function createExistence(
        FibExpression|ExthdrExpression|TcpOptionExpression|SctpChunkExpression $left,
        Existence $existence,
    ) : MatchStatement
    {
        $isFibType = ($left instanceof FibExpression && $left->getResult() === FibResult::TYPE);
        $isField = (!($left instanceof FibExpression) && $left->isField());

        if ($isFibType || $isField)
        {
            $message = "Only a whole header, option or chunk, or a fib lookup of an interface, can be checked for.";
            throw new BadArgumentException($message);
        }

        return new MatchStatement($left, Operator::EQUALS, $existence);
    }


    /**
     * Match the connection tracking state of a packet's connection, e.g. to accept anything that's part of an
     * established or related connection.
     *
     * @param ConnectionStateSet $states - the states.
     *
     * @param MatchMode $mode - whether to match connections that are, or aren't, in any of them. Defaults to are.
     *
     * @return MatchStatement
     */
    public static function createConnectionStates(
        ConnectionStateSet $states,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        $state = new CtExpression(CtKey::STATE);

        $result = ($mode === MatchMode::MATCHES)
            ? new MatchStatement($state, Operator::IN, $states)
            : new MatchStatement($state, Operator::NOT_EQUALS, new SetExpression(...$states->toJsonValue()));

        return $result;
    }


    /**
     * Match a packet's transport protocol (meta l4proto), whichever IP version it uses.
     *
     * @param Protocol $protocol - the protocol, e.g. TCP.
     *
     * @param MatchMode $mode - whether to match packets that do, or don't, use it. Defaults to do.
     *
     * @return MatchStatement
     */
    public static function createTransportProtocol(
        Protocol $protocol,
        MatchMode $mode = MatchMode::MATCHES,
    ) : MatchStatement
    {
        return new MatchStatement(new MetaExpression(MetaKey::L4PROTO), $mode->getOperator(), $protocol->value);
    }


    /**
     * Match ICMPv6 packets of some types (icmpv6 type { echo-request, echo-reply }), e.g. to accept pings. In an inet
     * table, it only matches IPv6 packets.
     *
     * @param Icmpv6Type ...$types - the types. At least one is needed.
     *
     * @return MatchStatement
     *
     * @throws BadArgumentException - if there are no types.
     */
    public static function createIcmpv6Types(Icmpv6Type ...$types) : MatchStatement
    {
        if (count($types) === 0)
        {
            throw new BadArgumentException("Matching ICMPv6 types needs at least one type.");
        }

        $names = array_values(array_unique(array_column($types, "value")));
        $right = (count($names) === 1) ? $names[0] : new SetExpression(...$names);
        return new MatchStatement(PayloadExpression::create(PayloadField::ICMPV6_TYPE), Operator::EQUALS, $right);
    }


    /**
     * Match TCP packets that start a new connection: those with SYN set, and FIN, RST and ACK not set. Combined with
     * ct state new, this stops packets that claim to be new without being a proper start of a connection.
     *
     * @return MatchStatement
     */
    public static function createTcpSyn() : MatchStatement
    {
        $flags = PayloadExpression::create(PayloadField::TCP_FLAGS);
        $checkedFlags = new BinaryOperationExpression(BinaryOperator::OR, "fin", "syn", "rst", "ack");
        $maskedFlags = new BinaryOperationExpression(BinaryOperator::AND, $flags, $checkedFlags);
        return new MatchStatement($maskedFlags, Operator::EQUALS, "syn");
    }


    /**
     * Create a match on a source or destination port.
     *
     * @param Protocol $protocol - the transport protocol.
     *
     * @param PacketEndpoint $endpoint - whether it's the source or destination port.
     *
     * @param int|PortSet|PortRange $ports - the ports.
     *
     * @param MatchMode $mode - whether the match is negated.
     *
     * @return MatchStatement
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535.
     */
    private static function createPortMatch(
        Protocol $protocol,
        PacketEndpoint $endpoint,
        int|PortSet|PortRange $ports,
        MatchMode $mode,
    ) : MatchStatement
    {
        if (is_int($ports))
        {
            NetworkLib::assertValidPort($ports);
        }

        $payload = PayloadExpression::create(PayloadField::from("{$protocol->value} {$endpoint->getPortField()}"));
        return new MatchStatement($payload, $mode->getOperator(), $ports);
    }


    /**
     * Create a match on a source or destination address.
     *
     * @param string $addressOrCidr - an IP address or network CIDR.
     *
     * @param PacketEndpoint $endpoint - whether it's the source or destination address.
     *
     * @param MatchMode $mode - whether the match is negated.
     *
     * @return MatchStatement
     *
     * @throws InvalidAddressException - if it isn't an IP address or network CIDR.
     */
    private static function createAddressMatch(
        string $addressOrCidr,
        PacketEndpoint $endpoint,
        MatchMode $mode,
    ) : MatchStatement
    {
        // The IP versions' values are the names of their headers, e.g. "ip6" for "ip6 saddr".
        $protocol = NetworkLib::getIpVersion($addressOrCidr)->value;
        $payload = PayloadExpression::create(PayloadField::from("{$protocol} {$endpoint->getAddressField()}"));

        $right = str_contains($addressOrCidr, "/")
            ? PrefixExpression::createFromCidr($addressOrCidr)
            : $addressOrCidr;

        return new MatchStatement($payload, $mode->getOperator(), $right);
    }
}
