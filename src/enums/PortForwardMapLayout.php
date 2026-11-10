<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * How RuleFactory::createMapPortForward() lays out its port forwards in named maps. Both forward the same traffic,
 * and differ in which nft can load them, and how they're changed at runtime.
 */
enum PortForwardMapLayout
{
    // One map, from each incoming port to an address and port together (a concatenation), e.g. "forwards", with
    // elements like 2222 : 10.0.0.2 . 22. Needs nft 1.1.3 (or RHEL 9's), as older nft crashes on such a map, or
    // silently drops it. A forward is added at runtime with one "nft add element".
    case ONE_MAP;

    // Two maps, from each incoming port to an address ("<name>_addresses") and to a port ("<name>_ports"). Works from
    // nft 0.9.8 up, so on every target. A forward added at runtime needs an "nft add element" in each map.
    case TWO_MAPS;
}
