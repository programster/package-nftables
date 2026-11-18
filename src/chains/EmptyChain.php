<?php

declare(strict_types=1);

namespace Programster\Nftables\Chains;

use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Tables\Table;

/**
 * A base chain with no rules, for a Ruleset, kept just for its policy, which applies to every packet it sees. E.g. on
 * a machine that mustn't route anything, a forward chain with a drop policy drops everything that would be forwarded.
 *
 * It isn't a Chain, so no rule can be created in it. A chain with rules doesn't need this, as its rules bring it into
 * the ruleset. A Ruleset refuses an empty chain with the same name, in the same table, as a chain that has rules.
 */
final readonly class EmptyChain
{
    // Only to check the arguments as a base chain's are checked, and never handed out, so no rule can be put in it.
    private BaseChain $m_chain;


    /**
     * Create an empty chain. The arguments are the same as for a BaseChain.
     *
     * @param string $name - the chain's name, which must be unique within its table.
     *
     * @param Table $table - the table the chain belongs to.
     *
     * @param ChainType $type - what the chain is for.
     *
     * @param ChainHook $hook - where in the network stack it sees packets.
     *
     * @param int|Priority $priority - the order it runs in, relative to other chains on the same hook (lowest first).
     *
     * @param Policy $policy - what happens to every packet the chain sees, as it has no rules to decide.
     *
     * @param string $device - the network device to attach to. Required for the ingress and egress hooks, and not
     * allowed for the others. Defaults to "", for none.
     *
     * @throws BadArgumentException - if the hook, type, priority or device can't be used in the table's family, or the
     * name is empty or too long.
     */
    public function __construct(
        string $name,
        Table $table,
        ChainType $type,
        ChainHook $hook,
        int|Priority $priority,
        Policy $policy,
        string $device = "",
    )
    {
        $this->m_chain = new BaseChain($name, $table, $type, $hook, $priority, $policy, $device);
    }


    # Accessors
    public function getName() : string { return $this->m_chain->getName(); }
    public function getTable() : Table { return $this->m_chain->getTable(); }
    public function getType() : ChainType { return $this->m_chain->getType(); }
    public function getHook() : ChainHook { return $this->m_chain->getHook(); }
    public function getPriority() : int|Priority { return $this->m_chain->getPriority(); }
    public function getPolicy() : Policy { return $this->m_chain->getPolicy(); }
    public function getDevice() : string { return $this->m_chain->getDevice(); }
}
