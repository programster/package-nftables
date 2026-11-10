<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\ChainHook;
use Programster\Nftables\Enums\ChainType;
use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Policy;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A chain attached to a hook in the network stack, so it sees every packet that passes that point.
 */
final readonly class BaseChain extends Chain
{
    private ChainType $m_type;
    private ChainHook $m_hook;
    private int|Priority $m_priority;
    private Policy $m_policy;
    private string $m_device;


    /**
     * Create a base chain.
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
     * Either a named priority, or any integer.
     *
     * @param Policy $policy - what happens to a packet that gets to the end of the chain without a verdict. There's no
     * default, so a chain never drops (or accepts) everything without that being chosen.
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
        parent::__construct($name, $table);
        $family = $table->getFamily();
        self::assertHookSuitsFamily($hook, $family);
        self::assertTypeSuitsHook($type, $hook, $family);

        if ($priority instanceof Priority)
        {
            // Throws if the name doesn't exist in this family.
            $priority->getValue($family);
        }

        $needsDevice = ($hook === ChainHook::INGRESS || $hook === ChainHook::EGRESS);

        if ($needsDevice !== ($device !== ""))
        {
            $message = $needsDevice
                ? "A chain on the {$hook->value} hook needs a device."
                : "Only chains on the ingress and egress hooks can have a device.";

            throw new BadArgumentException($message);
        }

        $this->m_type = $type;
        $this->m_hook = $hook;
        $this->m_priority = $priority;
        $this->m_policy = $policy;
        $this->m_device = $device;
    }


    public function toArray() : array
    {
        // Always a number: nft's JSON parser silently ignores a priority given as a name (or any other string), and
        // creates a regular chain with no hook, which sees no packets.
        $priority = ($this->m_priority instanceof Priority)
            ? $this->m_priority->getValue($this->m_table->getFamily())
            : $this->m_priority;

        $chain = [
            ...$this->getIdentifier(),
            "type" => $this->m_type->value,
            "hook" => $this->m_hook->value,
            "prio" => $priority,
            "policy" => $this->m_policy->value,
        ];

        if ($this->m_device !== "")
        {
            $chain["dev"] = $this->m_device;
        }

        return ["chain" => $chain];
    }


    /**
     * Check that a hook exists in a family.
     *
     * @param ChainHook $hook - the hook.
     *
     * @param Family $family - the family.
     *
     * @return void
     *
     * @throws BadArgumentException - if it doesn't.
     */
    private static function assertHookSuitsFamily(ChainHook $hook, Family $family) : void
    {
        $ipHooks = [
            ChainHook::PREROUTING,
            ChainHook::INPUT,
            ChainHook::FORWARD,
            ChainHook::OUTPUT,
            ChainHook::POSTROUTING,
        ];

        $hooks = match ($family) {
            Family::IP, Family::IP6, Family::BRIDGE => $ipHooks,
            Family::INET => [...$ipHooks, ChainHook::INGRESS],
            Family::ARP => [ChainHook::INPUT, ChainHook::OUTPUT],
            Family::NETDEV => [ChainHook::INGRESS, ChainHook::EGRESS],
        };

        if (!in_array($hook, $hooks, true))
        {
            throw new BadArgumentException("The {$family->value} family has no {$hook->value} hook.");
        }
    }


    /**
     * Check that a chain type can be used on a hook, in a family.
     *
     * @param ChainType $type - the chain type.
     *
     * @param ChainHook $hook - the hook.
     *
     * @param Family $family - the family.
     *
     * @return void
     *
     * @throws BadArgumentException - if it can't.
     */
    private static function assertTypeSuitsHook(ChainType $type, ChainHook $hook, Family $family) : void
    {
        $isIpFamily = in_array($family, [Family::IP, Family::IP6, Family::INET], true);
        $natHooks = [ChainHook::PREROUTING, ChainHook::INPUT, ChainHook::OUTPUT, ChainHook::POSTROUTING];

        $isSuitable = match ($type) {
            ChainType::FILTER => true,
            ChainType::NAT => $isIpFamily && in_array($hook, $natHooks, true),
            ChainType::ROUTE => $isIpFamily && $hook === ChainHook::OUTPUT,
        };

        if (!$isSuitable)
        {
            $message = "A {$type->value} chain can't go on the {$hook->value} hook in the {$family->value} family.";
            throw new BadArgumentException($message);
        }
    }


    # Accessors
    public function getType() : ChainType { return $this->m_type; }
    public function getHook() : ChainHook { return $this->m_hook; }
    public function getPriority() : int|Priority { return $this->m_priority; }
    public function getPolicy() : Policy { return $this->m_policy; }
    public function getDevice() : string { return $this->m_device; }
}
