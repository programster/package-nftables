<?php

namespace Programster\Nftables\Enums;
// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

enum NftablesChainType: string
{
    case FILTER = "filter"; // Supported by arp, bridge, ip, ip6 and inet table families.
    case ROUTE = "route"; // Mark packets (like mangle for the output hook, for other hooks use the type filter instead), supported by ip and ip6.
    case NAT = "nat"; // In order to perform Network Address Translation, supported by ip and ip6.
}
