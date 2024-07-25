<?php

// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

namespace Programster\Nftables\Enums;

enum NftablesChainHook: string
{
    case PREROUTING = "prerouting"; // sees all incoming packets, before any routing decision has been made. Packets may be addressed to the local or remote systems. - Supported by ip, ip6
    case INPUT = "input"; // sees incoming packets that are addressed to and have now been routed to the local system and processes running there. - applicable by to ip, ip6, and arp
    case FORWARD = "forward"; // sees incoming packets that are not addressed to the local system. - applicable to ip, ip6
    case OUTPUT = "output"; // sees packets that originated from processes in the local machine - applicable by to ip, ip6, and arp
    case POSTROUTING = "postrouting"; // sees all packets after routing, just before they leave the local system - applicable to ip, ip6
    case INGRESS = "ingress"; // applicable to netdev
    case EGRESS = "egress"; // applicable to netdev
}
