<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\ExceptionPortRequired;

readonly class PortSet
{
    private readonly array $m_ports;


    /**
     * Create a set of ports. This is useful for just allowing a pre-defined set of ports, such as 22, 80, and 443.
     * @param int ...$ports
     * @throws ExceptionPortRequired - when no ports were provided.
     */
    public function __construct(int ...$ports)
    {
        $ports = array_unique($ports);

        if (count($ports) === 0)
        {
            throw new ExceptionPortRequired();
        }

        $this->m_ports = $ports;
    }


    public function getPorts() { return $this->m_ports; }
}