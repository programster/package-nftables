<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\Verdict;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\Statements\GotoStatement;
use Programster\Nftables\Statements\JumpStatement;

/**
 * One element of a verdict map: a key, and the verdict for packets that have it, e.g. port 22 to accept (22 : accept),
 * or port 80 to a jump to the chain that handles web traffic (80 : jump web).
 */
final readonly class VerdictMapElement implements ReferencesTableItems
{
    private Expression|string|int $m_key;
    private Verdict|JumpStatement|GotoStatement $m_verdict;


    /**
     * Create a verdict map element.
     *
     * @param Expression|string|int $key - the key, e.g. a port, an address, a PortRange or PrefixExpression (in a map
     * with the INTERVAL flag), or a ConcatExpression (in a map whose key is a concatenation).
     *
     * @param Verdict|JumpStatement|GotoStatement $verdict - what to do with packets that have the key.
     *
     * @throws BadArgumentException - if the key is a string starting with "@".
     */
    public function __construct(Expression|string|int $key, Verdict|JumpStatement|GotoStatement $verdict)
    {
        // Converted here only to check it, so a bad value is caught where it's created.
        ExpressionLib::toJsonValue($key);
        $this->m_key = $key;
        $this->m_verdict = $verdict;
    }


    /**
     * Get the element in the form nftables expects, as a key and verdict pair.
     *
     * @return array
     */
    public function toJsonValue() : array
    {
        return [ExpressionLib::toJsonValue($this->m_key), $this->m_verdict->toArray()];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return TableItemLib::collectReferences($this->m_verdict);
    }


    # Accessors
    public function getKey() : Expression|string|int { return $this->m_key; }
    public function getVerdict() : Verdict|JumpStatement|GotoStatement { return $this->m_verdict; }
}
