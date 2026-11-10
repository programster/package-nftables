<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\CtDirection;
use Programster\Nftables\Enums\CtKey;
use Programster\Nftables\Enums\IpVersion;

/**
 * Connection tracking data about the connection a packet belongs to, e.g. its state, or its mark.
 */
final readonly class CtExpression implements Expression
{
    private CtKey $m_key;
    private ?CtDirection $m_direction;
    private ?IpVersion $m_ipVersion;


    /**
     * Create a connection tracking expression.
     *
     * @param CtKey $key - what to read, e.g. CtKey::STATE.
     *
     * @param CtDirection|null $direction - which direction of the connection to read, for the keys that have one
     * (e.g. SADDR). Defaults to null, for the keys that don't.
     *
     * @param IpVersion|null $ipVersion - the IP version, for the address keys (SADDR and DADDR). Defaults to null, for
     * the keys that don't need one.
     */
    public function __construct(CtKey $key, ?CtDirection $direction = null, ?IpVersion $ipVersion = null)
    {
        $this->m_key = $key;
        $this->m_direction = $direction;
        $this->m_ipVersion = $ipVersion;
    }


    public function toJsonValue() : array
    {
        $ct = ["key" => $this->m_key->value];

        if ($this->m_ipVersion !== null)
        {
            $ct["family"] = $this->m_ipVersion->value;
        }

        if ($this->m_direction !== null)
        {
            $ct["dir"] = $this->m_direction->value;
        }

        return ["ct" => $ct];
    }


    # Accessors
    public function getKey() : CtKey { return $this->m_key; }
}
