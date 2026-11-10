<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\NetworkLib;

/**
 * Sends the packet out of another network device straight away, skipping the rest of the network stack (fwd to
 * "eth1"), e.g. to bridge two devices with no routing at all. Only works in a netdev table, so needs the same nft
 * (1.0.6) as its chain.
 */
final readonly class FwdStatement implements Statement, ChainRestricted
{
    private array $m_body;


    private function __construct(array $body)
    {
        $this->m_body = $body;
    }


    /**
     * Send the packet out of a device, as it is.
     *
     * @param string $device - the network device.
     *
     * @return FwdStatement
     *
     * @throws BadArgumentException - if the device name is empty or too long.
     */
    public static function createToDevice(string $device) : FwdStatement
    {
        NetworkLib::assertValidDeviceName($device);
        return new FwdStatement(["dev" => $device]);
    }


    /**
     * Send the packet out of a device to a next hop, with its Ethernet header set for that hop, as routing would.
     *
     * @param string $device - the network device.
     *
     * @param string $address - the IPv4 or IPv6 address of the next hop, e.g. a router on that device's network.
     *
     * @return FwdStatement
     *
     * @throws BadArgumentException - if the device name is empty or too long.
     * @throws InvalidAddressException - if the address isn't an IP address (a network CIDR isn't allowed).
     */
    public static function createToAddress(string $device, string $address) : FwdStatement
    {
        NetworkLib::assertValidDeviceName($device);

        if (str_contains($address, "/"))
        {
            throw new InvalidAddressException("A packet can only be forwarded to an address, not a network CIDR.");
        }

        $ipVersion = NetworkLib::getIpVersion($address);
        return new FwdStatement(["dev" => $device, "family" => $ipVersion->value, "addr" => $address]);
    }


    public function toArray() : array
    {
        return ["fwd" => $this->m_body];
    }


    public function assertSuitsChain(BaseChain $chain) : void
    {
        $family = $chain->getTable()->getFamily();

        if ($family !== Family::NETDEV)
        {
            $message = "Forwarding to a device needs a netdev table, not a {$family->value} table.";
            throw new UnsuitableChainException($message);
        }
    }
}
