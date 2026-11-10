<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A field in a TCP option, for a TcpOptionExpression. Each value is the option, then the field, as nftables writes
 * them (e.g. "maxseg size").
 */
enum TcpOptionField : string
{
    case MAXSEG_SIZE = "maxseg size";
    case WINDOW_COUNT = "window count";

    // The first block of a selective acknowledgement (which nft also calls sack0).
    case SACK_LEFT = "sack left";
    case SACK_RIGHT = "sack right";

    case SACK1_LEFT = "sack1 left";
    case SACK1_RIGHT = "sack1 right";
    case SACK2_LEFT = "sack2 left";
    case SACK2_RIGHT = "sack2 right";
    case SACK3_LEFT = "sack3 left";
    case SACK3_RIGHT = "sack3 right";
    case TIMESTAMP_TSVAL = "timestamp tsval";
    case TIMESTAMP_TSECR = "timestamp tsecr";


    /**
     * Get the option part, e.g. "maxseg" for MAXSEG_SIZE.
     *
     * @return string
     */
    public function getOption() : string
    {
        return explode(" ", $this->value, 2)[0];
    }


    /**
     * Get the field part, e.g. "size" for MAXSEG_SIZE.
     *
     * @return string
     */
    public function getField() : string
    {
        return explode(" ", $this->value, 2)[1];
    }
}
