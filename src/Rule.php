<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\StatementCollection;
use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\Statements\ChainRestricted;
use Programster\Nftables\Statements\Statement;

/**
 * A rule in a chain: a list of statements, applied to each packet in order. A match that fails skips the rest of the
 * rule. Create one with create(), or RuleFactory for the common ones.
 */
final readonly class Rule
{
    // nft's limit.
    private const MAX_COMMENT_BYTES = 128;

    private Chain $m_chain;

    private StatementCollection $m_statements;

    private string $m_comment;

    // The chains, sets, maps, flowtables and named objects this rule uses.
    private TableItemCollection $m_referencedItems;


    /**
     * Create a rule. Use create() and withComment().
     *
     * @param Chain $chain - the chain the rule belongs to.
     *
     * @param string $comment - a comment to show with the rule in "nft list ruleset", or "" for none.
     *
     * @param Statement ...$statements - what the rule does, in order. At least one is needed.
     *
     * @throws BadArgumentException - if there are no statements, or the comment is longer than 128 bytes.
     *
     * @throws UnsuitableChainException - if the rule uses a chain, set, map, flowtable or named object from a different
     * table, or a statement that its chain can't have.
     */
    private function __construct(Chain $chain, string $comment, Statement ...$statements)
    {
        if (count($statements) === 0)
        {
            throw new BadArgumentException("A rule needs at least one statement.");
        }

        if (strlen($comment) > self::MAX_COMMENT_BYTES)
        {
            throw new BadArgumentException("A rule comment can be at most " . self::MAX_COMMENT_BYTES . " bytes long.");
        }

        foreach ($statements as $statement)
        {
            if ($statement instanceof ChainRestricted && $chain instanceof BaseChain)
            {
                $statement->assertSuitsChain($chain);
            }
        }

        $referencedItems = TableItemLib::collectReferences(...$statements);
        TableItemLib::assertAllInTable($chain->getTable(), "A rule", $referencedItems);
        $this->m_chain = $chain;
        $this->m_statements = new StatementCollection(array_values($statements));
        $this->m_comment = $comment;
        $this->m_referencedItems = $referencedItems;
    }


    /**
     * Create a rule.
     *
     * @param Chain $chain - the chain the rule belongs to.
     *
     * @param Statement ...$statements - what the rule does, in order, e.g. some MatchStatements and then a Verdict. At
     * least one is needed.
     *
     * @return Rule
     *
     * @throws BadArgumentException - if there are no statements.
     *
     * @throws UnsuitableChainException - if the rule uses a chain, set, map, flowtable or named object from a different
     * table, or a statement that its chain can't have (e.g. flow offloading anywhere but the forward hook).
     */
    public static function create(Chain $chain, Statement ...$statements) : Rule
    {
        return new Rule($chain, "", ...$statements);
    }


    /**
     * Get a copy of the rule with a comment, which "nft list ruleset" shows with it.
     *
     * @param string $comment - the comment, or "" for none. It can be at most 128 bytes, the most nft handles.
     *
     * @return Rule
     *
     * @throws BadArgumentException - if the comment is longer than 128 bytes.
     */
    public function withComment(string $comment) : Rule
    {
        return new Rule($this->m_chain, $comment, ...$this->m_statements->toArray());
    }


    /**
     * Get the rule in the form nftables expects.
     *
     * @return array
     */
    public function toArray() : array
    {
        $expressions = [];

        foreach ($this->m_statements as $statement)
        {
            $expressions[] = $statement->toArray();
        }

        $rule = [
            "family" => $this->getTable()->getFamily()->value,
            "table" => $this->getTable()->getName(),
            "chain" => $this->m_chain->getName(),
            "expr" => $expressions,
        ];

        if ($this->m_comment !== "")
        {
            $rule["comment"] = $this->m_comment;
        }

        return ["rule" => $rule];
    }


    # Accessors
    public function getChain() : Chain { return $this->m_chain; }
    public function getTable() : Table { return $this->m_chain->getTable(); }
    public function getStatements() : StatementCollection { return clone $this->m_statements; }
    public function getComment() : string { return $this->m_comment; }
    public function getReferencedItems() : TableItemCollection { return clone $this->m_referencedItems; }
}
