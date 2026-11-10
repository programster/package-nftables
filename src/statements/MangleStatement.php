<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\CtKey;
use Programster\Nftables\Enums\MetaKey;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\CtExpression;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\Expressions\MetaExpression;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\TableItemLib;

/**
 * Changes part of a packet, or its metadata, e.g. sets its mark, so later rules or routing can act on it.
 */
final readonly class MangleStatement implements Statement, ReferencesTableItems
{
    private const MAX_MARK = 0xFFFFFFFF;

    private Expression $m_key;
    private Expression|string|int $m_value;


    /**
     * Create a mangle statement.
     *
     * @param Expression $key - what to change, e.g. a MetaExpression for the packet's mark.
     *
     * @param Expression|string|int $value - what to change it to.
     *
     * @throws BadArgumentException - if $value is a string starting with "@".
     */
    public function __construct(Expression $key, Expression|string|int $value)
    {
        ExpressionLib::toJsonValue($value);
        $this->m_key = $key;
        $this->m_value = $value;
    }


    /**
     * Set the packet's mark (meta mark set), which lasts until it leaves this machine.
     *
     * @param int $mark - the mark, from 0 to 0xFFFFFFFF.
     *
     * @return MangleStatement
     *
     * @throws BadArgumentException - if the mark is out of range.
     */
    public static function createSetMetaMark(int $mark) : MangleStatement
    {
        self::assertValidMark($mark);
        return new MangleStatement(new MetaExpression(MetaKey::MARK), $mark);
    }


    /**
     * Set the connection's mark (ct mark set), which every later packet of the connection has.
     *
     * @param int $mark - the mark, from 0 to 0xFFFFFFFF.
     *
     * @return MangleStatement
     *
     * @throws BadArgumentException - if the mark is out of range.
     */
    public static function createSetCtMark(int $mark) : MangleStatement
    {
        self::assertValidMark($mark);
        return new MangleStatement(new CtExpression(CtKey::MARK), $mark);
    }


    public function toArray() : array
    {
        $mangle = ["key" => $this->m_key->toJsonValue(), "value" => ExpressionLib::toJsonValue($this->m_value)];
        return ["mangle" => $mangle];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return TableItemLib::collectReferences($this->m_key, $this->m_value);
    }


    /**
     * Check a mark fits in the 32 bits a mark has.
     *
     * @param int $mark - the mark.
     *
     * @return void
     *
     * @throws BadArgumentException - if it doesn't.
     */
    private static function assertValidMark(int $mark) : void
    {
        if ($mark < 0 || $mark > self::MAX_MARK)
        {
            throw new BadArgumentException("A mark must be between 0 and 0xFFFFFFFF, not {$mark}.");
        }
    }
}
