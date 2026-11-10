<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A conntrack helper, for a CtHelper object. Each understands one protocol whose connections open further connections
 * (e.g. FTP's data connections), so they can be recognised as related, and NATed to match. Each needs its kernel module
 * (e.g. nf_conntrack_ftp), which nft loads when it can.
 */
enum CtHelperType
{
    case FTP;
    case TFTP;
    case IRC;
    case SIP_UDP;
    case SIP_TCP;
    case PPTP;
    case SANE;
    case AMANDA;
    case NETBIOS_NS;
    case H323_RAS;
    case H323_Q931;
    case SNMP;
    case SNMP_TRAP;

    /**
     * Get the helper's name in the kernel.
     *
     * @return string - e.g. "ftp".
     */
    public function getHelperName() : string
    {
        return match ($this) {
            self::FTP => "ftp",
            self::TFTP => "tftp",
            self::IRC => "irc",
            self::SIP_UDP, self::SIP_TCP => "sip",
            self::PPTP => "pptp",
            self::SANE => "sane",
            self::AMANDA => "amanda",
            self::NETBIOS_NS => "netbios-ns",
            self::H323_RAS => "RAS",
            self::H323_Q931 => "Q.931",
            self::SNMP => "snmp",
            self::SNMP_TRAP => "snmp_trap",
        };
    }


    /**
     * Get the transport protocol the helper works with.
     *
     * @return Protocol
     */
    public function getProtocol() : Protocol
    {
        return match ($this) {
            self::FTP, self::IRC, self::SIP_TCP, self::PPTP, self::SANE, self::H323_Q931 => Protocol::TCP,
            self::TFTP, self::SIP_UDP, self::AMANDA, self::NETBIOS_NS, self::H323_RAS => Protocol::UDP,
            self::SNMP, self::SNMP_TRAP => Protocol::UDP,
        };
    }
}
