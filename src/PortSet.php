<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;

/**
 * A set of individual ports, such as 22, 80 and 443.
 */
final readonly class PortSet implements Expression
{
    /** @var int[] */
    private array $m_ports;


    /**
     * Create a set of ports. Duplicates are ignored.
     *
     * @param int ...$ports - the ports. At least one is needed.
     *
     * @throws BadArgumentException - if there are no ports, or one isn't between 1 and 65535.
     */
    public function __construct(int ...$ports)
    {
        if (count($ports) === 0)
        {
            throw new BadArgumentException("A port set needs at least one port.");
        }

        foreach ($ports as $port)
        {
            NetworkLib::assertValidPort($port);
        }

        $this->m_ports = array_values(array_unique($ports));
    }


    public function toJsonValue() : array|int
    {
        return (count($this->m_ports) === 1) ? $this->m_ports[0] : ["set" => $this->m_ports];
    }


    # Accessors
    public function getPorts() : array { return $this->m_ports; }
}
