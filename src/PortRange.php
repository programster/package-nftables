<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;

/**
 * A range of ports, from one to another inclusive, e.g. 5000-6000.
 */
final readonly class PortRange implements Expression
{
    private int $m_minPort;
    private int $m_maxPort;


    /**
     * Create a port range.
     *
     * @param int $minPort - the lowest port in the range.
     *
     * @param int $maxPort - the highest port in the range, which must be above $minPort. For a single port, use the
     * port on its own.
     *
     * @throws BadArgumentException - if either port isn't between 1 and 65535, or $maxPort isn't above $minPort.
     */
    public function __construct(int $minPort, int $maxPort)
    {
        NetworkLib::assertValidPort($minPort);
        NetworkLib::assertValidPort($maxPort);

        if ($minPort >= $maxPort)
        {
            throw new BadArgumentException("A port range's max port ({$maxPort}) must be above its min ({$minPort}).");
        }

        $this->m_minPort = $minPort;
        $this->m_maxPort = $maxPort;
    }


    public function toJsonValue() : array
    {
        return ["range" => [$this->m_minPort, $this->m_maxPort]];
    }


    /**
     * Check whether another range covers exactly the same ports.
     *
     * @param PortRange $other - the range to compare with.
     *
     * @return bool
     */
    public function equals(PortRange $other) : bool
    {
        return $this->m_minPort === $other->getMinPort() && $this->m_maxPort === $other->getMaxPort();
    }


    # Accessors
    public function getMinPort() : int { return $this->m_minPort; }
    public function getMaxPort() : int { return $this->m_maxPort; }
}
