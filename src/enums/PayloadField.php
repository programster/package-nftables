<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A named field in a packet header, for a PayloadExpression. Each value is the protocol, then the field, as
 * nftables writes them (e.g. "tcp dport"). th is whichever transport header the packet has.
 */
enum PayloadField : string
{
    case ETHER_SADDR = "ether saddr";
    case ETHER_DADDR = "ether daddr";
    case ETHER_TYPE = "ether type";
    case VLAN_ID = "vlan id";
    case VLAN_DEI = "vlan dei";
    case VLAN_PCP = "vlan pcp";
    case VLAN_TYPE = "vlan type";
    case ARP_HTYPE = "arp htype";
    case ARP_PTYPE = "arp ptype";
    case ARP_HLEN = "arp hlen";
    case ARP_PLEN = "arp plen";
    case ARP_OPERATION = "arp operation";
    case ARP_SADDR_IP = "arp saddr ip";
    case ARP_SADDR_ETHER = "arp saddr ether";
    case ARP_DADDR_IP = "arp daddr ip";
    case ARP_DADDR_ETHER = "arp daddr ether";
    case IP_VERSION = "ip version";
    case IP_HDRLENGTH = "ip hdrlength";
    case IP_DSCP = "ip dscp";
    case IP_ECN = "ip ecn";
    case IP_LENGTH = "ip length";
    case IP_ID = "ip id";
    case IP_FRAG_OFF = "ip frag-off";
    case IP_TTL = "ip ttl";
    case IP_PROTOCOL = "ip protocol";
    case IP_CHECKSUM = "ip checksum";
    case IP_SADDR = "ip saddr";
    case IP_DADDR = "ip daddr";
    case ICMP_TYPE = "icmp type";
    case ICMP_CODE = "icmp code";
    case ICMP_CHECKSUM = "icmp checksum";
    case ICMP_ID = "icmp id";
    case ICMP_SEQUENCE = "icmp sequence";
    case ICMP_GATEWAY = "icmp gateway";
    case ICMP_MTU = "icmp mtu";
    case IGMP_TYPE = "igmp type";
    case IGMP_MRT = "igmp mrt";
    case IGMP_CHECKSUM = "igmp checksum";
    case IGMP_GROUP = "igmp group";
    case IP6_VERSION = "ip6 version";
    case IP6_DSCP = "ip6 dscp";
    case IP6_ECN = "ip6 ecn";
    case IP6_FLOWLABEL = "ip6 flowlabel";
    case IP6_LENGTH = "ip6 length";
    case IP6_NEXTHDR = "ip6 nexthdr";
    case IP6_HOPLIMIT = "ip6 hoplimit";
    case IP6_SADDR = "ip6 saddr";
    case IP6_DADDR = "ip6 daddr";
    case ICMPV6_TYPE = "icmpv6 type";
    case ICMPV6_CODE = "icmpv6 code";
    case ICMPV6_CHECKSUM = "icmpv6 checksum";
    case ICMPV6_PARAMETER_PROBLEM = "icmpv6 parameter-problem";
    case ICMPV6_PACKET_TOO_BIG = "icmpv6 packet-too-big";
    case ICMPV6_ID = "icmpv6 id";
    case ICMPV6_SEQUENCE = "icmpv6 sequence";
    case ICMPV6_MAX_DELAY = "icmpv6 max-delay";
    case TCP_SPORT = "tcp sport";
    case TCP_DPORT = "tcp dport";
    case TCP_SEQUENCE = "tcp sequence";
    case TCP_ACKSEQ = "tcp ackseq";
    case TCP_DOFF = "tcp doff";
    case TCP_RESERVED = "tcp reserved";
    case TCP_FLAGS = "tcp flags";
    case TCP_WINDOW = "tcp window";
    case TCP_CHECKSUM = "tcp checksum";
    case TCP_URGPTR = "tcp urgptr";
    case UDP_SPORT = "udp sport";
    case UDP_DPORT = "udp dport";
    case UDP_LENGTH = "udp length";
    case UDP_CHECKSUM = "udp checksum";
    case UDPLITE_SPORT = "udplite sport";
    case UDPLITE_DPORT = "udplite dport";
    case UDPLITE_CHECKSUM = "udplite checksum";
    case SCTP_SPORT = "sctp sport";
    case SCTP_DPORT = "sctp dport";
    case SCTP_VTAG = "sctp vtag";
    case SCTP_CHECKSUM = "sctp checksum";
    case DCCP_SPORT = "dccp sport";
    case DCCP_DPORT = "dccp dport";
    case DCCP_TYPE = "dccp type";
    case AH_NEXTHDR = "ah nexthdr";
    case AH_HDRLENGTH = "ah hdrlength";
    case AH_RESERVED = "ah reserved";
    case AH_SPI = "ah spi";
    case AH_SEQUENCE = "ah sequence";
    case ESP_SPI = "esp spi";
    case ESP_SEQUENCE = "esp sequence";
    case COMP_NEXTHDR = "comp nexthdr";
    case COMP_FLAGS = "comp flags";
    case COMP_CPI = "comp cpi";
    case TH_SPORT = "th sport";
    case TH_DPORT = "th dport";

    /**
     * Get the protocol (header) part, e.g. "tcp" for TCP_DPORT.
     *
     * @return string
     */
    public function getProtocol() : string
    {
        return explode(" ", $this->value, 2)[0];
    }


    /**
     * Get the field part, e.g. "dport" for TCP_DPORT.
     *
     * @return string
     */
    public function getField() : string
    {
        return explode(" ", $this->value, 2)[1];
    }
}
