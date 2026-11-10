<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A field in an IPv6 extension header, for an ExthdrExpression. Each value is the header, then the field, as
 * nftables writes them (e.g. "frag more-fragments").
 */
enum Ipv6ExtensionHeaderField : string
{
    case HBH_NEXTHDR = "hbh nexthdr";
    case HBH_HDRLENGTH = "hbh hdrlength";
    case RT_NEXTHDR = "rt nexthdr";
    case RT_HDRLENGTH = "rt hdrlength";
    case RT_TYPE = "rt type";
    case RT_SEG_LEFT = "rt seg-left";
    case FRAG_NEXTHDR = "frag nexthdr";
    case FRAG_FRAG_OFF = "frag frag-off";
    case FRAG_MORE_FRAGMENTS = "frag more-fragments";
    case FRAG_ID = "frag id";
    case DST_NEXTHDR = "dst nexthdr";
    case DST_HDRLENGTH = "dst hdrlength";
    case MH_NEXTHDR = "mh nexthdr";
    case MH_HDRLENGTH = "mh hdrlength";
    case MH_TYPE = "mh type";
    case MH_CHECKSUM = "mh checksum";


    /**
     * Get the header part, e.g. "frag" for FRAG_MORE_FRAGMENTS.
     *
     * @return string
     */
    public function getHeader() : string
    {
        return explode(" ", $this->value, 2)[0];
    }


    /**
     * Get the field part, e.g. "more-fragments" for FRAG_MORE_FRAGMENTS.
     *
     * @return string
     */
    public function getField() : string
    {
        return explode(" ", $this->value, 2)[1];
    }
}
