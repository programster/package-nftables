<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\ChainLib;
use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\NetworkLib;

/**
 * Sends the packet to a local socket (a transparent proxy) without changing its destination, so the proxy can see where
 * it was going, unlike a RedirectStatement. Only works in a filter chain on the prerouting hook, and needs a match on
 * the transport protocol (e.g. MatchFactory::createTransportProtocol()) earlier in the rule.
 *
 * It also needs routing set up so the packets are delivered locally, and a proxy that listens with IP_TRANSPARENT. The
 * usual setup marks the packets (MangleStatement::createSetMetaMark()) in the same rule, and routes marked packets to
 * the loopback interface (ip rule add fwmark 1 lookup 100, and ip route add local 0.0.0.0/0 dev lo table 100).
 */
final readonly class TproxyStatement implements Statement, ChainRestricted
{
    private IpVersion $m_ipVersion;
    private array $m_body;


    private function __construct(IpVersion $ipVersion, array $body)
    {
        $this->m_ipVersion = $ipVersion;
        $this->m_body = $body;
    }


    /**
     * Send packets to a port on whichever local address they arrived at.
     *
     * @param IpVersion $ipVersion - the IP version of the packets, which nft needs to know.
     *
     * @param int $port - the port the proxy listens on.
     *
     * @return TproxyStatement
     *
     * @throws BadArgumentException - if the port isn't between 1 and 65535.
     */
    public static function createToPort(IpVersion $ipVersion, int $port) : TproxyStatement
    {
        NetworkLib::assertValidPort($port);
        return new TproxyStatement($ipVersion, ["family" => $ipVersion->value, "port" => $port]);
    }


    /**
     * Send packets to a local address, and optionally a port.
     *
     * @param string $address - the IPv4 or IPv6 address the proxy listens on.
     *
     * @param int|null $port - the port the proxy listens on. Defaults to null, which keeps each packet's port.
     *
     * @return TproxyStatement
     *
     * @throws InvalidAddressException - if the address isn't an IP address (a network CIDR isn't allowed).
     * @throws BadArgumentException - if the port isn't between 1 and 65535.
     */
    public static function createToAddress(string $address, ?int $port = null) : TproxyStatement
    {
        if (str_contains($address, "/"))
        {
            throw new InvalidAddressException("A transparent proxy needs an address, not a network CIDR.");
        }

        $ipVersion = NetworkLib::getIpVersion($address);
        $body = ["family" => $ipVersion->value, "addr" => $address];

        if ($port !== null)
        {
            NetworkLib::assertValidPort($port);
            $body["port"] = $port;
        }

        return new TproxyStatement($ipVersion, $body);
    }


    public function toArray() : array
    {
        return ["tproxy" => $this->m_body];
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        ChainLib::assertChainIs($chain, ChainType::FILTER, "use a transparent proxy", ChainHook::PREROUTING);
        ChainLib::assertIpFamily($chain, "use a transparent proxy");
        $family = $chain->getTable()->getFamily();

        $suitableFamily = ($this->m_ipVersion === IpVersion::IPV4) ? Family::IP : Family::IP6;

        if ($family !== $suitableFamily && $family !== Family::INET)
        {
            $needs = "an {$suitableFamily->value} or inet table";
            $message = "A transparent proxy for {$this->m_ipVersion->name} needs {$needs}, not {$family->value}.";
            throw new UnsuitableChainException($message);
        }
    }
}
