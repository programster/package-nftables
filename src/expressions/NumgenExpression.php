<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\NumgenMode;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A number generated for each packet, from $offset up to $offset + $modulus - 1, e.g. to spread new connections over
 * several machines by looking it up in a map (dnat to numgen inc mod 2 map { 0 : 10.0.0.1, 1 : 10.0.0.2 }), or to
 * sample a share of the traffic. Use it on new connections only (ct state new), as NAT remembers each connection's
 * translation for the rest of its packets anyway.
 */
final readonly class NumgenExpression implements Expression
{
    private NumgenMode $m_mode;
    private int $m_modulus;
    private int $m_offset;


    /**
     * Create a number generator.
     *
     * @param NumgenMode $mode - whether to count up (taking turns), or pick at random.
     *
     * @param int $modulus - how many different numbers to generate, e.g. 2 for 0 and 1.
     *
     * @param int $offset - the first number. Defaults to 0.
     *
     * @throws BadArgumentException - if the modulus isn't positive, the offset is negative, or the numbers don't fit in
     * 32 bits.
     */
    public function __construct(NumgenMode $mode, int $modulus, int $offset = 0)
    {
        HashExpression::assertValidRange($modulus, $offset);
        $this->m_mode = $mode;
        $this->m_modulus = $modulus;
        $this->m_offset = $offset;
    }


    public function toJsonValue() : array
    {
        return ["numgen" => ["mode" => $this->m_mode->value, "mod" => $this->m_modulus, "offset" => $this->m_offset]];
    }
}
