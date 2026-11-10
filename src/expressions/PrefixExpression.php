<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\InvalidAddressException;
use Programster\Nftables\NetworkLib;

/**
 * A network, given as a CIDR prefix, e.g. 10.0.0.0/8.
 */
final readonly class PrefixExpression implements Expression
{
    private string $m_address;
    private int $m_length;


    /**
     * Create a prefix.
     *
     * @param string $address - the network's address, with all its host bits zero, e.g. 10.0.0.0.
     *
     * @param int $length - the prefix length, e.g. 8.
     *
     * @throws InvalidAddressException - if they don't make a network CIDR.
     */
    public function __construct(string $address, int $length)
    {
        NetworkLib::assertValidNetworkCidr("{$address}/{$length}");
        $this->m_address = $address;
        $this->m_length = $length;
    }


    /**
     * Create a prefix from a CIDR string.
     *
     * @param string $cidr - a network CIDR, e.g. 10.0.0.0/8 or fd00::/8.
     *
     * @return PrefixExpression
     *
     * @throws InvalidAddressException - if it isn't a network CIDR.
     */
    public static function createFromCidr(string $cidr) : PrefixExpression
    {
        NetworkLib::assertValidNetworkCidr($cidr);
        [$address, $length] = explode("/", $cidr);
        return new PrefixExpression($address, (int)$length);
    }


    public function toJsonValue() : array
    {
        return ["prefix" => ["addr" => $this->m_address, "len" => $this->m_length]];
    }


    # Accessors
    public function getAddress() : string { return $this->m_address; }
    public function getLength() : int { return $this->m_length; }
}
