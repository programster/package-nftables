<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Statements\SynproxyStatement;
use Programster\Nftables\Table;

/**
 * A named synproxy, which any number of rules can share (synproxy name "web"), so its settings are only written once.
 * See SynproxyStatement for what it does, and the rest of the setup it needs.
 *
 * Needs nft 1.1.3 (or RHEL 9's), as older nft can't read one from JSON, and kernel 5.3.
 */
final readonly class NamedSynproxy extends NamedObject
{
    private SynproxyStatement $m_synproxy;


    /**
     * Create a named synproxy.
     *
     * @param string $name - the synproxy's name, which must be unique among the synproxies in its table.
     *
     * @param Table $table - the table it belongs to.
     *
     * @param SynproxyStatement $synproxy - the settings.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Table $table, SynproxyStatement $synproxy)
    {
        parent::__construct($name, $table);
        $this->m_synproxy = $synproxy;
    }


    public function toArray() : array
    {
        return ["synproxy" => [...$this->getIdentifier(), ...$this->m_synproxy->toArray()["synproxy"]]];
    }


    # Accessors
    public function getSynproxy() : SynproxyStatement { return $this->m_synproxy; }
}
