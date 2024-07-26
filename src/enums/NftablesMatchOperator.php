<?php

namespace Programster\Nftables\Enums;

// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tables

enum NftablesMatchOperator: string
{
    case EQUALS = "==";
    case IN = "in";
}
