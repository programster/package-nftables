<?php

namespace Programster\Nftables\Enums;
enum NftablesConnectionState: string
{
    case NEW = "new";
    case RELATED = "related";
    case ESTABLISHED = "established";
    case UNTRACKED = "untracked";
}
