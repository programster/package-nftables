<?php

namespace Programster\Nftables\Enums;

// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

enum NftablesPolicy: string
{
    case ACCEPT = "accept"; // accept the packets
    case DROP = "drop"; // drop the packets
}
