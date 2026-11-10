<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Enums\Family;
use Programster\Nftables\Enums\Priority;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A flowtable, a fast path for forwarded connections. Once a rule in the forward chain offloads a connection to it (see
 * FlowOffloadStatement, or RuleFactory::createFlowOffload()), the connection's packets are forwarded as soon as they
 * arrive on one of the flowtable's devices, skipping the rest of the network stack: the prerouting, forward and
 * postrouting chains, and routing. That makes forwarding much cheaper, e.g. on a router or NAT gateway.
 *
 * Only TCP and UDP connections can be offloaded. A connection's first packets take the normal path, through the
 * chains, and the rest take the fast path once a rule has offloaded it. NAT still applies to offloaded connections,
 * but the forward chain's rules no longer see their packets, so a rule added later to block a connection won't affect
 * one that's already offloaded. A connection leaves the flowtable when it closes, or is idle for a while.
 *
 * Needs nft 1.0.6, as older nft can't read a flowtable's devices from JSON.
 */
final readonly class Flowtable implements TableItem
{
    // The kernel's limit for an interface name, which includes a terminating null byte.
    private const MAX_DEVICE_BYTES = 15;

    private string $m_name;
    private Table $m_table;
    private int|Priority $m_priority;

    /** @var string[] - without duplicates. */
    private array $m_devices;


    /**
     * Create a flowtable.
     *
     * @param string $name - the flowtable's name, which must be unique among the flowtables in its table.
     *
     * @param Table $table - the table it belongs to, which must be an ip, ip6 or inet table. Only rules in the same
     * table can offload to it.
     *
     * @param int|Priority $priority - the order its fast path runs in, relative to chains on the ingress hook of the
     * same devices. Priority::FILTER (0) suits most uses.
     *
     * @param string ...$devices - the network devices whose connections it handles, e.g. "eth0" and "eth1" for the
     * WAN and LAN sides of a router. Both sides of a connection need to be in it. At least one is needed.
     *
     * @throws BadArgumentException - if the table isn't an ip, ip6 or inet table, there are no devices, a device name
     * is empty or too long, or the name is empty or too long.
     */
    public function __construct(string $name, Table $table, int|Priority $priority, string ...$devices)
    {
        NameLib::assertValidName($name, "flowtable");
        $family = $table->getFamily();

        if (!in_array($family, [Family::IP, Family::IP6, Family::INET], true))
        {
            throw new BadArgumentException("A flowtable needs an ip, ip6 or inet table, not {$family->value}.");
        }

        if (count($devices) === 0)
        {
            throw new BadArgumentException("A flowtable needs at least one device.");
        }

        foreach ($devices as $device)
        {
            if ($device === "" || strlen($device) > self::MAX_DEVICE_BYTES)
            {
                $message = "A device name must be from 1 to " . self::MAX_DEVICE_BYTES . " bytes long.";
                throw new BadArgumentException($message);
            }
        }

        if ($priority instanceof Priority)
        {
            // Throws if the name doesn't exist in this family.
            $priority->getValue($family);
        }

        $this->m_name = $name;
        $this->m_table = $table;
        $this->m_priority = $priority;
        $this->m_devices = array_values(array_unique($devices));
    }


    public function toArray() : array
    {
        // Always a number, as for a chain's priority.
        $priority = ($this->m_priority instanceof Priority)
            ? $this->m_priority->getValue($this->m_table->getFamily())
            : $this->m_priority;

        $flowtable = [
            "family" => $this->m_table->getFamily()->value,
            "table" => $this->m_table->getName(),
            "name" => $this->m_name,
            "hook" => "ingress",
            "prio" => $priority,
            "dev" => $this->m_devices,
        ];

        return ["flowtable" => $flowtable];
    }


    # Accessors
    public function getName() : string { return $this->m_name; }
    public function getTable() : Table { return $this->m_table; }
    public function getPriority() : int|Priority { return $this->m_priority; }
    public function getDevices() : array { return $this->m_devices; }
}
