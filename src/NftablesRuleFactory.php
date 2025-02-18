<?php

namespace Programster\Nftables;

use Programster\Nftables\Enums\NftablesChainType;
use Programster\Nftables\Enums\NftablesChainHook;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Exceptions\ExceptionUnsuitableChain;

readonly class NftablesRuleFactory
{
    /**
     * Private constructor as this class is not meant to be instantiated.
     */
    private function __construct()
    {

    }


    /**
     * Create a masquerade rule, that will cause nftables to mangle the packets that go out
     * so that they appear to come from this server, rather than where they originally came
     * from.
     * @param NftablesChain $postRoutingChain
     * @param string $outputInterfaceName
     * @return NftablesRule - the created rule.
     * @throws ExceptionUnsuitableChain - if the chain provided as a parameter is unsuitable
     */
    public static function createMasquerade(
        NftablesChain $postRoutingChain,
        string $outputInterfaceName,
        ?string $comment = null,
    ) : NftablesRule
    {
        if ($postRoutingChain->getHook() !== NftablesChainHook::POSTROUTING)
        {
            throw new ExceptionUnsuitableChain("The masquerade rule needs to apply to a chain that uses the postrouting hook.");
        }

        $expressions = [
            NftablesMatchFactory::createMatchOutputInterfaceName($outputInterfaceName),
            [ "masquerade" => null ]
        ];

        return new NftablesRule($postRoutingChain, $expressions, $comment);
    }


    /**
     * Create a NAT rule for port forwarding. This is the rule that performs the network address translation (NAT)
     * mangling of the packets, so that their destination is changed to the other IP address, and possibly a different
     * port. Depending in how your forwarding chain is setup (e.g. if you don't have an accept policy on your forwarding
     * chain), then you may need to run createForwardingRule as well to add forwarding rules.
     * @param NftablesChain $preroutingChain - specify the chain that we are going to add this rule to.
     * @param string $inputInterfaceName - specify the name of the interface to accept the traffic on for forwarding.
     * This is typically the WAN interface.
     * @param int $inputPort - specify the port we are expected to listen out for for traffic to be forwarded.
     * @param string $newDestIp - specify the IP address you wish the packets to go to next. When setting up a NAT, this
     * will typically be the internal/private IP of  your internal server that you wish to forward traffic onto.
     * @param int $newDestPort - specify the port the traffic should be forwarded to.
     * @param Protocol $protocol - specify whether the traffic should be TCP/UDP.
     * @param string|null $sourceIpCidr - optionally provide an IP or CIDR for where the traffice must be coming from
     * for it to be matched against in order to be forwarded.
     * @return NftablesRule
     * @throws ExceptionUnsuitableChain
     * @throws Exceptions\ExceptionPortRequired
     */
    public static function createPortForwardNatRule(
        NftablesChain $preroutingChain,
        string        $inputInterfaceName,
        int           $inputPort,
        string        $newDestIp,
        int           $newDestPort,
        Protocol      $protocol = Protocol::TCP,
        ?string       $sourceIpCidr = null,
        ?string       $comment = null,
    ) : NftablesRule
    {
        // not sure if should allow the forwarding hook too.
        if ($preroutingChain->getHook() !== NftablesChainHook::PREROUTING)
        {
            throw new ExceptionUnsuitableChain("The chain used for an NAT port rule needs to use the PREROUTING hook.");
        }

        if ($preroutingChain->getType() !== NftablesChainType::NAT)
        {
            throw new Exception("The chain used for an NAT port rule needs to use the NAT type.");
        }

        $matches = [
            NftablesMatchFactory::createMatchInputInterfaceName($inputInterfaceName),
            NftablesMatchFactory::createMatchDestinationPorts($protocol, $inputPort),
        ];

        if ($sourceIpCidr !== null)
        {
            $matches[] = NftablesMatchFactory::createMatchSourceIpOrCidr($sourceIpCidr);
        }

        $expressions = [
            ...$matches,
            NftablesLib::createDnat($newDestIp, $newDestPort)
        ];

        return new NftablesRule($preroutingChain, $expressions, $comment);
    }


    public static function createPortRangeForwardNatRule(
        NftablesChain $preroutingChain,
        string        $inputInterfaceName,
        PortRange     $inputPorts,
        string        $newDestIp,
        PortRange     $destPorts,
        Protocol      $protocol = Protocol::TCP,
        ?string       $sourceIpCidr = null,
        ?string       $comment = null,
    ) : NftablesRule
    {
        // not sure if should allow the forwarding hook too.
        if ($preroutingChain->getHook() !== NftablesChainHook::PREROUTING)
        {
            throw new ExceptionUnsuitableChain("The chain used for an NAT port rule needs to use the PREROUTING hook.");
        }

        if ($preroutingChain->getType() !== NftablesChainType::NAT)
        {
            throw new Exception("The chain used for an NAT port rule needs to use the NAT type.");
        }

        $matches = [
            NftablesMatchFactory::createMatchInputInterfaceName($inputInterfaceName),
            NftablesMatchFactory::createMatchDestinationPortRange($protocol, $inputPorts),
        ];

        if ($sourceIpCidr !== null)
        {
            $matches[] = NftablesMatchFactory::createMatchSourceIpOrCidr($sourceIpCidr);
        }

        $expressions = [
            ...$matches,
            NftablesLib::createDnat($newDestIp, $destPorts)
        ];

        return new NftablesRule($preroutingChain, $expressions, $comment);
    }



    /**
     * Create a forwarding rule, typically for things like port forwarding.
     * @param NftablesChain $forwardFilteringChain - the forwarding chain this rule needs adding to
     * @param string $inputInterface - the interface the forwarding traffic must be coming in on.
     * @param string $outputInterface - the output interface the forwarding traffic must be wanting to go out on.
     * @param bool $checkForSynPacketType - whether to only allow traffic that is flagged SYN, which is used in TCP
     * connections for establishing a new connection. E.g.  you may wish to create a rule that allows connection state
     * "new" but only if this is set to true.
     * https://www.digitalocean.com/community/tutorials/how-to-forward-ports-through-a-linux-gateway-with-iptables#adding-forwarding-rules-to-the-basic-firewall
     * @param NftablesConnectionStateCollection|null $allowedStates - A list of possible connection states that will
     * be allowed. E.g. one will typically want to allow through RELATED/ESTABLISHED tcp connections.
     * @param Protocol $protocol - the protocol (TCP/UDP)
     * @param int|null $destPort - the port of the connection.
     * @param string|null $sourceIpOrCidr - where the traffic is being forwarded from.
     * @param string|null $destIpOrCidr - the destination the traffic is being forwarded to.
     * @param string|null $comment - an optional comment.
     * @return NftablesRule
     * @throws Exceptions\ExceptionConnectionStateRequired
     * @throws Exceptions\ExceptionPortRequired
     */
    public static function createForwardingRule(
        NftablesChain $forwardFilteringChain,
        string        $inputInterface,
        string        $outputInterface,
        bool          $checkForSynPacketType,
        ?NftablesConnectionStateCollection $allowedStates = null,
        Protocol      $protocol = Protocol::TCP,
        ?int          $destPort = null,
        ?string       $sourceIpOrCidr = null,
        ?string       $destIpOrCidr = null,
        ?string       $comment = null,
    ) : NftablesRule
    {
        if ($forwardFilteringChain->getHook() !== NftablesChainHook::FORWARD)
        {
            throw new Exception("The chain used for an forwarding rule needs to use the FORWARD hook.");
        }

        if ($forwardFilteringChain->getType() !== NftablesChainType::FILTER)
        {
            throw new Exception("The chain used for an forwarding rules needs to use the FILTER type.");
        }

        if ($checkForSynPacketType && $protocol !== Protocol::TCP)
        {
            throw new Exception("Checking for SYN package type is only applicable to TCP connections.");
        }

        $expressions = [
            NftablesMatchFactory::createMatchInputInterfaceName($inputInterface),
            NftablesMatchFactory::createMatchOutputInterfaceName($outputInterface),
        ];

        if ($allowedStates !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchConnectionStates(...$allowedStates->getStates());
        }

        if ($checkForSynPacketType)
        {
            $expressions[] = NftablesMatchFactory::createMatchTcpSynFlag();
        }

        if (count($sourceIpOrCidr) !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchSourceIpOrCidr($sourceIpOrCidr);
        }

        if (count($destIpOrCidr) !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationIpOrCidr($sourceIpOrCidr);
        }

        if ($destPort !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationPorts($protocol, $destPort);
        }

        return new NftablesRule($forwardFilteringChain, $expressions, $comment);
    }


    /**
     * Create a rule for accepting input traffic on a certain port or set of ports and possibly other conditions, such
     * as where it came from. This is particularly useful for if you just wish to open a port such as 80 for accepting
     * HTTP traffic for this server to handle, or to pass on with a port forwarding rule elsewhere in the chain.
     * @param NftablesChain $inputFilterChain
     * @param string $interfaceName
     * @param int|PortSet|PortRange $incomingPortOrPorts - the port or the set/range of ports to accept
     * @param Protocol $protocol - the protocol. E.g tcp or UDP.
     * @param string|null $destIpOrCidr - optionally specify the destination IP of the traffic.
     * @param string|null $sourceIpOrCidr - optionally specify the source IP or CIDR of the traffice
     * @param NftablesConnectionStateCollection|null $allowedStates
     * @param string|null $comment
     * @return NftablesRule
     * @throws ExceptionUnsuitableChain
     * @throws Exceptions\ExceptionConnectionStateRequired
     * @throws Exceptions\ExceptionPortRequired
     */
    public static function createAcceptPort(
        NftablesChain         $inputFilterChain,
        string                $interfaceName,
        int|PortSet|PortRange $incomingPortOrPorts,
        Protocol              $protocol = Protocol::TCP,
        ?string               $destIpOrCidr = null,
        ?string               $sourceIpOrCidr = null,
        ?NftablesConnectionStateCollection $allowedStates = null,
        ?string               $comment = null,
    ) : NftablesRule
    {
        if ($inputFilterChain->getType() !== NftablesChainType::FILTER)
        {
            throw new ExceptionUnsuitableChain("The type of chain used for an accept network interface rule needs to be of type FILTER..");
        }

        if ($inputFilterChain->getHook() !== NftablesChainHook::INPUT)
        {
            throw new ExceptionUnsuitableChain("The chain used for an accept network interface rule needs to use the INPUT hook.");
        }

        $expressions = [
            NftablesMatchFactory::createMatchInputInterfaceName($interfaceName),
        ];

        if ($incomingPortOrPorts instanceof PortRange)
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationPortRange($protocol, $incomingPortOrPorts);
        }
        else if($incomingPortOrPorts instanceof PortSet)
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationPorts($protocol, ...$incomingPortOrPorts->getPorts());
        }
        else if(is_int($incomingPortOrPorts))
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationPorts($protocol, $incomingPortOrPorts);
        }
        else
        {
            throw new Exception("Whoops! Something unforeseen has gone wrong.");
        }

        if ($destIpOrCidr !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchDestinationIpOrCidr($destIpOrCidr);
        }

        if ($sourceIpOrCidr !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchSourceIpOrCidr($sourceIpOrCidr);
        }

        if ($allowedStates !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchConnectionStates(...$allowedStates->getStates());
        }

        $expressions[] = ["accept" => null];
        return new NftablesRule($inputFilterChain, $expressions, $comment);
    }
    

    /**
     * Creates a rule that just says we accept everything on an interface. You typically want to do this
     *  on interfaces like "lo" for the local loopback interface.
     * @param string $interfaceName
     * @param NftablesChain $inputChain - the chain this rule should apply to
     * @param NftablesConnectionStateCollection|null $allowedStates - optionally specify the connection states the
     * connection must be in to be accepted. E.g. it is common to allow WAN inputs if the connection is in a related or
     * established state, from the server having made an outbound tcp connection for which it expects a response. If not
     * provided, then all states will be accepted.
     * @return NftablesRule
     * @throws ExceptionUnsuitableChain - if the chain provided is unsuitable
     */
    public static function createAcceptNetworkInterfaceInput(
        string $interfaceName,
        NftablesChain $inputChain,
        ?NftablesConnectionStateCollection $allowedStates = null,
        ?string $comment = null,
    ) : NftablesRule
    {
        if ($inputChain->getType() !== NftablesChainType::FILTER)
        {
            throw new ExceptionUnsuitableChain("The type of chain used for an accept network interface rule needs to be of type FILTER..");
        }

        if ($inputChain->getHook() !== NftablesChainHook::INPUT)
        {
            throw new ExceptionUnsuitableChain("The chain used for an accept network interface rule needs to use the INPUT hook.");
        }

        $expressions = [
            NftablesMatchFactory::createMatchInputInterfaceName($interfaceName),
        ];

        if ($allowedStates !== null)
        {
            $expressions[] = NftablesMatchFactory::createMatchConnectionStates(...$allowedStates->getStates());
        }

        $expressions[] = ["accept" => null];
        return new NftablesRule($inputChain, $expressions, $comment);
    }
}
