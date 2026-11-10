<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A hash of part of the packet, from $offset up to $offset + $modulus - 1, so packets with the same values always get
 * the same number, e.g. to always send a client to the same machine by looking it up in a map
 * (dnat to jhash ip saddr mod 2 map { 0 : 10.0.0.1, 1 : 10.0.0.2 }).
 */
final readonly class HashExpression implements Expression
{
    // The numbers are 32 bits.
    private const MAX_VALUE = 0xFFFFFFFF;

    private array $m_value;


    private function __construct(array $value)
    {
        $this->m_value = $value;
    }


    /**
     * Create a Jenkins hash of any values from the packet (jhash).
     *
     * @param Expression $input - what to hash, e.g. a PayloadExpression for the source address, or a ConcatExpression
     * of several values.
     *
     * @param int $modulus - how many different numbers to give, e.g. 2 for 0 and 1.
     *
     * @param int $offset - the first number. Defaults to 0.
     *
     * @param int|null $seed - the hash's seed. The same packet gets the same number for as long as the seed stays the
     * same. Defaults to null, which lets the kernel pick a random one each time the ruleset is loaded.
     *
     * @return HashExpression
     *
     * @throws BadArgumentException - if the modulus isn't positive, the offset or seed is negative, or the numbers or
     * seed don't fit in 32 bits.
     */
    public static function createJhash(
        Expression $input,
        int $modulus,
        int $offset = 0,
        ?int $seed = null,
    ) : HashExpression
    {
        self::assertValidRange($modulus, $offset);
        $hash = ["mod" => $modulus, "offset" => $offset, "expr" => $input->toJsonValue()];

        if ($seed !== null)
        {
            if ($seed < 0 || $seed > self::MAX_VALUE)
            {
                throw new BadArgumentException("A hash seed must be from 0 to 0xFFFFFFFF.");
            }

            $hash["seed"] = $seed;
        }

        return new HashExpression(["jhash" => $hash]);
    }


    /**
     * Create a symmetric hash of the packet's addresses and ports (symhash), which is the same for both directions of
     * a connection, e.g. so the replies go the same way as the requests.
     *
     * @param int $modulus - how many different numbers to give, e.g. 2 for 0 and 1.
     *
     * @param int $offset - the first number. Defaults to 0.
     *
     * @return HashExpression
     *
     * @throws BadArgumentException - if the modulus isn't positive, the offset is negative, or the numbers don't fit in
     * 32 bits.
     */
    public static function createSymhash(int $modulus, int $offset = 0) : HashExpression
    {
        self::assertValidRange($modulus, $offset);
        return new HashExpression(["symhash" => ["mod" => $modulus, "offset" => $offset]]);
    }


    /**
     * Check that a modulus and offset give numbers that fit in 32 bits. Also used by NumgenExpression.
     *
     * @param int $modulus - how many different numbers there are.
     *
     * @param int $offset - the first number.
     *
     * @return void
     *
     * @throws BadArgumentException - if the modulus isn't positive, the offset is negative, or the numbers don't fit.
     *
     * @internal
     */
    public static function assertValidRange(int $modulus, int $offset) : void
    {
        if ($modulus < 1 || $offset < 0 || $offset + $modulus - 1 > self::MAX_VALUE)
        {
            throw new BadArgumentException("A modulus must be at least 1, and the numbers must fit in 32 bits.");
        }
    }


    public function toJsonValue() : array
    {
        return $this->m_value;
    }
}
