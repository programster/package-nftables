<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;

/**
 * One port forward, for RuleFactory::createMapPortForward(): traffic arriving on a port is sent to a port on another
 * machine, e.g. port 2222 to port 22 on 10.0.0.2.
 */
final readonly class PortForward
{
    private int $m_incomingPort;
    private string $m_address;
    private int $m_port;
    private IpVersion $m_ipVersion;


    /**
     * Create a port forward.
     *
     * @param int $incomingPort - the port the traffic arrives on.
     *
     * @param string $address - the IPv4 or IPv6 address of the machine to send it to (not a network CIDR).
     *
     * @param int $port - the port to send it to on that machine.
     *
     * @throws BadArgumentException - if a port isn't between 1 and 65535.
     * @throws InvalidAddressException - if the address isn't an IP address.
     */
    public function __construct(int $incomingPort, string $address, int $port)
    {
        NetworkLib::assertValidPort($incomingPort);
        NetworkLib::assertValidPort($port);

        if (str_contains($address, "/"))
        {
            $message = "A port forward needs an address, not a network CIDR, but got {$address}.";
            throw new InvalidAddressException($message);
        }

        $this->m_ipVersion = NetworkLib::getIpVersion($address);
        $this->m_incomingPort = $incomingPort;
        $this->m_address = $address;
        $this->m_port = $port;
    }


    # Accessors
    public function getIncomingPort() : int { return $this->m_incomingPort; }
    public function getAddress() : string { return $this->m_address; }
    public function getPort() : int { return $this->m_port; }
    public function getIpVersion() : IpVersion { return $this->m_ipVersion; }
}
