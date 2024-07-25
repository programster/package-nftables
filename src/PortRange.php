<?php

namespace Programster\Nftables;


readonly class PortRange
{
    public function __construct(public int $minPort, public int $maxPort)
    {
        if ($minPort >= $maxPort)
        {
            throw new \Exception("The min port needs to be less than the max port.");
        }
    }
}