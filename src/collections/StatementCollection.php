<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Statements\Statement;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of statements, e.g. a rule's, in the order they're applied. Anything that isn't a Statement is rejected as
 * it's added.
 *
 * @extends AbstractCollection<Statement>
 */
final class StatementCollection extends AbstractCollection
{
    public function getType() : string
    {
        return Statement::class;
    }
}
