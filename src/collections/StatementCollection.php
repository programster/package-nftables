<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Statements\Statement;

/**
 * A list of statements, e.g. a rule's, in the order they're applied. It can't be changed once it's created, so it can
 * be shared freely.
 *
 * @extends AbstractReadonlyCollection<Statement>
 */
final readonly class StatementCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of statements, in the order they're applied.
     * @param Statement ...$statements - the statements, in the order they're applied. There can be none.
     */
    public function __construct(Statement ...$statements)
    {
        parent::__construct(...$statements);
    }
}
