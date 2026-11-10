<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\OsfKey;
use Programster\Nftables\Enums\OsfTtlCheck;

/**
 * The operating system a TCP SYN packet looks like it came from, found by passive fingerprinting (osf name), e.g. to
 * compare with "Linux". It's a guess from how the packet's TCP options are laid out, which a client can fake, so it
 * suits logging and statistics better than security.
 *
 * The kernel only knows the fingerprints that have been loaded into it (e.g. with nfnl_osf from the iptables package,
 * and the pf.os file). Without them, every packet is "unknown".
 *
 * Needs kernel 4.19, so isn't available on RHEL 8.
 */
final readonly class OsfExpression implements Expression
{
    private OsfKey $m_key;
    private OsfTtlCheck $m_ttlCheck;


    /**
     * Create an operating system fingerprint expression.
     *
     * @param OsfKey $key - whether to give the operating system's name, or its name and version.
     *
     * @param OsfTtlCheck $ttlCheck - how to compare the packet's TTL with the fingerprints'. Defaults to EXACT, nft's
     * default, which only works for machines on the same network. Use LOOSE for packets from the internet.
     */
    public function __construct(OsfKey $key, OsfTtlCheck $ttlCheck = OsfTtlCheck::EXACT)
    {
        $this->m_key = $key;
        $this->m_ttlCheck = $ttlCheck;
    }


    public function toJsonValue() : array
    {
        $osf = ["key" => $this->m_key->value];

        $ttl = match ($this->m_ttlCheck) {
            OsfTtlCheck::EXACT => "",
            OsfTtlCheck::LOOSE => "loose",
            OsfTtlCheck::SKIP => "skip",
        };

        if ($ttl !== "")
        {
            $osf["ttl"] = $ttl;
        }

        return ["osf" => $osf];
    }
}
