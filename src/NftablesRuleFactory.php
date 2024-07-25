<?php

namespace Programster\Nftables;

use Programster\Nftables\Enums\NftablesChainType;
use Programster\Nftables\Enums\NftablesChainHook;
use Programster\Nftables\Enums\Protocol;
use Programster\Nftables\Exceptions\ExceptionUnsuitableChain;

readonly class NftablesRuleFactory
{
    /**
     * Create a masquerade rule, that will cause nftables to mangle the packets that go out
     * so that they appear to come from this server, rather than where they originally came
     * from.
     * @param NftablesChain $postRoutingChain
     * @param string $outputInterfaceName
     * @return array[]
     * @throws ExceptionUnsuitableChain - if the chain provided as a parameter is unsuitable
     */
    public static function createMasqueradeRule(NftablesChain $postRoutingChain, string $outputInterfaceName) : array
    {
        if ($postRoutingChain->getHook() !== NftablesChainHook::POSTROUTING)
        {
            throw new ExceptionUnsuitableChain("The masquerade rule needs to apply to a chain that uses the postrouting hook.");
        }

        return [
            "rule" => [
                "family" => $postRoutingChain->getTable()->getFamily()->value,
                "table" => $postRoutingChain->getTable()->getName(),
                "chain" => $postRoutingChain->getName(),
                "expr" => [
                    NftablesMatchFactory::createMatchOutputInterfaceName($outputInterfaceName),
                    [
                        "masquerade" => null
                    ]
                ]
            ]
        ];
    }


    /**
     * Create a port forwarding rule.
     * @param NftablesChain $preroutingChain - specify the chain that we are going to add this rule to.
     * @param string $incomingInterfaceName - specify the name of the interface to accept the traffic on for forwarding.
     * This is typically the WAN interface.
     * @param int $incomingPortNumber - specify the port we are expected to listen out for for traffic to be forwarded.
     * @param string $internalServerIp - specify the IP of the internal server the traffic should be forwarded to.
     * @param int $internalServerPort - specify the internal port the traffic should be forwarded to.
     * @param Protocol $protocol - specify whether the traffic should be TCP/UDP.
     * @param string|null $sourceIpCidr - optionally provide an IP or CIDR for where the traffice must be coming from
     * for it to be matched against in order to be forwarded.
     * @return array[]
     * @throws ExceptionUnsuitableChain
     * @throws Exceptions\ExceptionPortRequired
     */
    public static function createPortForwardingRule(
        NftablesChain $preroutingChain,
        string   $incomingInterfaceName,
        int      $incomingPortNumber,
        string   $internalServerIp,
        int      $internalServerPort,
        Protocol $protocol = Protocol::TCP,
        ?string  $sourceIpCidr = null,
    ) : array
    {
        // not sure if should allow the forwarding hook too.
        if (in_array($preroutingChain->getHook()->value, ["prerouting"]) === false)
        {
            throw new ExceptionUnsuitableChain("Port forwarding rule must be applied to a chain that uses the prerouting hook.");
        }

        $matches = [
            NftablesMatchFactory::createMatchInputInterfaceName($incomingInterfaceName),
            NftablesMatchFactory::createMatchDestinationPorts($protocol, $incomingPortNumber),
        ];

        if ($sourceIpCidr !== null)
        {
            $matches[] = NftablesMatchFactory::createMatchSourceIpOrCidr($sourceIpCidr);
        }

        return [
            "rule" => [
                "family" => $preroutingChain->getTable()->getFamily()->value,
                "table" =>  $preroutingChain->getTable()->getName(),
                "chain" => $preroutingChain->getName(),
                "expr" => [
                    ...$matches,
                    NftablesLib::createDnat($internalServerIp, $internalServerPort)
                ]
            ]
        ];
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
     * @return array[] - the rule in array form.
     * @throws ExceptionUnsuitableChain - if the chain provided is unsuitable
     */
    public static function createAcceptNetworkInterfaceInputRule(
        string $interfaceName,
        NftablesChain $inputChain,
        ?NftablesConnectionStateCollection $allowedStates = null
    ) : array
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

        return [
            "rule" => [
                "family" => $inputChain->getTable()->getFamily(),
                "table" => $inputChain->getTable()->getName(),
                "chain" => $inputChain->getName(),
                "expr" => $expressions
            ]
        ];
    }
}