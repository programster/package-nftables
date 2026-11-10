<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\NetworkLib;

/**
 * Sends a copy of the packet somewhere else, while the original carries on as normal, e.g. to mirror traffic to an
 * intrusion detection system. In an ip or ip6 table, the copy goes to an address (dup to 10.0.0.9). In a netdev table,
 * it goes out of a network device as it is (dup to "eth2").
 */
final readonly class DupStatement implements Statement, ChainRestricted
{
    // The family of table it can go in.
    private Family $m_family;
    private array $m_body;


    private function __construct(Family $family, array $body)
    {
        $this->m_family = $family;
        $this->m_body = $body;
    }


    /**
     * Send a copy of the packet to an address, routed as normal, or out of a device. Only works in an ip or ip6 table
     * of the address's IP version (not an inet one).
     *
     * @param string $address - the IPv4 or IPv6 address to send the copy to, e.g. the machine that inspects it.
     *
     * @param string $device - optionally, the network device to send it out of, rather than the one routing picks.
     * Defaults to "", for routing to pick.
     *
     * @return DupStatement
     *
     * @throws InvalidAddressException - if the address isn't an IP address (a network CIDR isn't allowed).
     * @throws BadArgumentException - if the device name is too long.
     */
    public static function createToAddress(string $address, string $device = "") : DupStatement
    {
        if (str_contains($address, "/"))
        {
            throw new InvalidAddressException("A copy can only be sent to an address, not a network CIDR.");
        }

        $family = (NetworkLib::getIpVersion($address) === IpVersion::IPV4) ? Family::IP : Family::IP6;
        $body = ["addr" => $address];

        if ($device !== "")
        {
            NetworkLib::assertValidDeviceName($device);
            $body["dev"] = $device;
        }

        return new DupStatement($family, $body);
    }


    /**
     * Send a copy of the packet out of a network device, as it is. Only works in a netdev table.
     *
     * @param string $device - the network device, e.g. a mirror port.
     *
     * @return DupStatement
     *
     * @throws BadArgumentException - if the device name is empty or too long.
     */
    public static function createToDevice(string $device) : DupStatement
    {
        NetworkLib::assertValidDeviceName($device);

        // nft names the device "addr" here.
        return new DupStatement(Family::NETDEV, ["addr" => $device]);
    }


    public function toArray() : array
    {
        return ["dup" => $this->m_body];
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        $family = $chain->getTable()->getFamily();

        if ($family !== $this->m_family)
        {
            $message = "This copy can only go in a table of the {$this->m_family->value} family, not {$family->value}.";
            throw new UnsuitableChainException($message);
        }
    }
}
