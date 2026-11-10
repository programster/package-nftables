<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Table;

/**
 * A security mark, which a rule gives packets (meta secmark set "ssh"), so the security module's policy (e.g.
 * SELinux) can decide which programs may send and receive them. Loading it fails unless the security module knows the
 * context.
 *
 * Using one in a rule needs nft 1.0.6, as older nft can't read that from JSON.
 */
final readonly class Secmark extends NamedObject
{
    // The kernel's limit, which includes a terminating null byte.
    private const MAX_CONTEXT_BYTES = 255;

    private string $m_context;


    /**
     * Create a security mark.
     *
     * @param string $name - the mark's name, which must be unique among the security marks in its table.
     *
     * @param Table $table - the table it belongs to.
     *
     * @param string $context - the security context, e.g. "system_u:object_r:ssh_server_packet_t:s0" for SELinux.
     *
     * @throws BadArgumentException - if the context is empty or too long, or the name is empty or too long.
     */
    public function __construct(string $name, Table $table, string $context)
    {
        parent::__construct($name, $table);

        if ($context === "" || strlen($context) > self::MAX_CONTEXT_BYTES)
        {
            $message = "A security context must be from 1 to " . self::MAX_CONTEXT_BYTES . " bytes long.";
            throw new BadArgumentException($message);
        }

        $this->m_context = $context;
    }


    public function toArray() : array
    {
        return ["secmark" => [...$this->getIdentifier(), "context" => $this->m_context]];
    }
}
