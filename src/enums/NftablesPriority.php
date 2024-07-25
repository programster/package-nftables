<?php

namespace Programster\Nftables\Enums;

//refers to a number used to order the chains or to set them between some Netfilter operations.
// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

enum NftablesPriority: int
{
    case NF_IP_PRI_CONNTRACK_DEFRAG = -400;
    case NF_IP_PRI_RAW = -300;
    case NF_IP_PRI_SELINUX_FIRST = -225;
    case NF_IP_PRI_CONNTRACK = -200;
    case NF_IP_PRI_MANGLE = -150;
    case NF_IP_PRI_NAT_DST = -100;
    case NF_IP_PRI_FILTER = 0;
    case NF_IP_PRI_SECURITY = 50;
    case NF_IP_PRI_NAT_SRC = 100;
    case NF_IP_PRI_SELINUX_LAST = 225;
    case NF_IP_PRI_CONNTRACK_HELPER = 300;




}
