<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\IpVersion;
use Programster\Nftables\Enums\RtKey;

/**
 * Routing data about the packet, e.g. the MTU of its route, to clamp TCP's maximum segment size to it.
 */
final readonly class RtExpression implements Expression
{
    private RtKey $m_key;
    private ?IpVersion $m_ipVersion;


    /**
     * Create a routing expression.
     *
     * @param RtKey $key - what to read.
     *
     * @param IpVersion|null $ipVersion - optionally, the IP version, which NEXTHOP needs in an inet table. Defaults to
     * null, for none.
     */
    public function __construct(RtKey $key, ?IpVersion $ipVersion = null)
    {
        $this->m_key = $key;
        $this->m_ipVersion = $ipVersion;
    }


    public function toJsonValue() : array
    {
        $rt = ["key" => $this->m_key->value];

        if ($this->m_ipVersion !== null)
        {
            $rt["family"] = $this->m_ipVersion->value;
        }

        return ["rt" => $rt];
    }
}
