<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\IpsecDirection;
use Programster\Nftables\Enums\IpsecKey;
use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\PacketEndpoint;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Something about the IPsec security association a packet arrived through, or will leave through, e.g. to only accept
 * traffic from one tunnel (ipsec in reqid 1). A packet that didn't (or won't) go through IPsec doesn't match. To
 * just check whether it went through IPsec at all, match MetaKey::SECPATH instead.
 *
 * The direction limits which hooks it can be used on (see IpsecDirection), which the kernel checks when the ruleset
 * loads.
 */
final readonly class IpsecExpression implements Expression
{
    // The most security associations a packet can go through, as nft counts them from 0.
    private const MAX_SPNUM = 255;

    private array $m_value;


    private function __construct(array $value)
    {
        $this->m_value = $value;
    }


    /**
     * Read the request ID or SPI of a security association.
     *
     * @param IpsecDirection $direction - whether it's the association the packet arrived or will leave through.
     *
     * @param IpsecKey $key - what to read.
     *
     * @param int $associationNumber - which association, from 0, for a packet that went through more than one (e.g.
     * nested tunnels). Defaults to 0, the first.
     *
     * @return IpsecExpression
     *
     * @throws BadArgumentException - if the association number isn't from 0 to 255.
     */
    public static function create(
        IpsecDirection $direction,
        IpsecKey $key,
        int $associationNumber = 0,
    ) : IpsecExpression
    {
        $value = ["key" => $key->value, "dir" => $direction->value, ...self::createSpnum($associationNumber)];
        return new IpsecExpression(["ipsec" => $value]);
    }


    /**
     * Read the source or destination address of a security association's tunnel, e.g. to only accept traffic that came
     * through the tunnel from one gateway.
     *
     * @param IpsecDirection $direction - whether it's the association the packet arrived or will leave through.
     *
     * @param PacketEndpoint $endpoint - whether to read the tunnel's source or destination address.
     *
     * @param IpVersion $ipVersion - the IP version of the tunnel's addresses.
     *
     * @param int $associationNumber - which association, from 0. Defaults to 0, the first.
     *
     * @return IpsecExpression
     *
     * @throws BadArgumentException - if the association number isn't from 0 to 255.
     */
    public static function createAddress(
        IpsecDirection $direction,
        PacketEndpoint $endpoint,
        IpVersion $ipVersion,
        int $associationNumber = 0,
    ) : IpsecExpression
    {
        $key = ($endpoint === PacketEndpoint::SOURCE) ? "saddr" : "daddr";
        $spnum = self::createSpnum($associationNumber);
        $value = ["key" => $key, "dir" => $direction->value, "family" => $ipVersion->value, ...$spnum];
        return new IpsecExpression(["ipsec" => $value]);
    }


    public function toJsonValue() : array
    {
        return $this->m_value;
    }


    /**
     * Get the part of the expression that says which association it's about.
     *
     * @param int $associationNumber - the association, from 0.
     *
     * @return array - empty for the first, which is nft's default.
     *
     * @throws BadArgumentException - if it isn't from 0 to 255.
     */
    private static function createSpnum(int $associationNumber) : array
    {
        if ($associationNumber < 0 || $associationNumber > self::MAX_SPNUM)
        {
            throw new BadArgumentException("An IPsec association number must be from 0 to " . self::MAX_SPNUM . ".");
        }

        return ($associationNumber === 0) ? [] : ["spnum" => $associationNumber];
    }
}
