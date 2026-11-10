<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\StatementCollection;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\SetUpdateOperation;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\NamedSet;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\TableItemLib;

/**
 * Adds a value from the packet to a named set, updates it, or deletes it, as packets arrive, e.g. to remember the
 * addresses that have knocked on a port (add @knocked { ip saddr }), so a later rule can let them in.
 *
 * Each element it adds can also carry its own counter, limit or quota, which is what nft's meters are, e.g. to drop
 * the traffic of any address sending more than 10 new connections a second (add @flood { ip saddr limit rate over
 * 10/second } drop). A statement in the braces is applied to the packet, and the rule only carries on if it matches.
 * These need nft 1.0.6, as older nft silently drops them.
 *
 * As traffic decides what goes in the set, adding or updating needs the set to have a size (see NamedSet::withSize()),
 * so it can't be made to fill memory, e.g. by packets from spoofed addresses, and a timeout (see
 * NamedSet::withTimeout()), so old elements make room for new ones. Once the set is full, the rule stops at this
 * statement until elements expire, so without a timeout, a meter would quietly stop limiting new addresses for good.
 * (nft 0.9.8 also can't load a set update to a set with a size but no timeout.)
 */
final readonly class SetUpdateStatement implements Statement, ReferencesTableItems
{
    private SetUpdateOperation $m_operation;
    private NamedSet $m_set;
    private Expression|string|int $m_element;

    // Each a CounterStatement, LimitStatement or QuotaStatement, which the constructor enforces.
    private StatementCollection $m_statements;


    /**
     * Create a set update.
     *
     * @param SetUpdateOperation $operation - whether to add, update or delete the element.
     *
     * @param NamedSet $set - the set. To add or update, it must have a size and a timeout. Its type must suit the
     * element.
     *
     * @param Expression|string|int $element - the value to add, e.g. a PayloadExpression for the packet's source
     * address, or a ConcatExpression for a set of concatenations.
     *
     * @param CounterStatement|LimitStatement|QuotaStatement ...$statements - optionally, statements for each element to
     * carry, applied to the packet each time it reaches here (only when adding or updating).
     *
     * @throws BadArgumentException - if the set has no size or timeout for an add or update, statements are given for
     * a delete, or the element is a string starting with "@".
     */
    public function __construct(
        SetUpdateOperation $operation,
        NamedSet $set,
        Expression|string|int $element,
        CounterStatement|LimitStatement|QuotaStatement ...$statements,
    )
    {
        $isDelete = ($operation === SetUpdateOperation::DELETE);

        if (!$isDelete && ($set->getMaxElements() === 0 || $set->getTimeoutSeconds() === 0))
        {
            $message = "A set that rules add to needs a size and a timeout, so traffic can't fill it up for good. See"
                . " NamedSet::withSize() and NamedSet::withTimeout().";

            throw new BadArgumentException($message);
        }

        if ($isDelete && count($statements) > 0)
        {
            throw new BadArgumentException("Deleting an element from a set can't apply statements to it.");
        }

        // Converted here only to check it, so a bad value is caught where it's created.
        ExpressionLib::toJsonValue($element);
        $this->m_operation = $operation;
        $this->m_set = $set;
        $this->m_element = $element;
        $this->m_statements = new StatementCollection(array_values($statements));
    }


    public function toArray() : array
    {
        $update = [
            "op" => $this->m_operation->value,
            "elem" => ExpressionLib::toJsonValue($this->m_element),
            "set" => "@{$this->m_set->getName()}",
        ];

        if (count($this->m_statements) > 0)
        {
            $update["stmt"] = [];

            foreach ($this->m_statements as $statement)
            {
                $update["stmt"][] = $statement->toArray();
            }
        }

        return ["set" => $update];
    }


    public function getReferencedItems() : TableItemCollection
    {
        $items = TableItemLib::collectReferences($this->m_element);
        $items->add($this->m_set);
        return $items;
    }
}
