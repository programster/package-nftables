<?php

declare(strict_types=1);

namespace Programster\Nftables\Testing;

use JsonException;
use RuntimeException;

/**
 * Reads values out of decoded JSON (nftables' JSON, or a toArray()), checking each is there and of the type expected,
 * so a test reading the wrong place fails saying where, rather than comparing against null.
 */
final class JsonLib
{
    private function __construct()
    {
    }


    /**
     * Decode a JSON object.
     * @param string $json - the JSON, e.g. nft's JSON listing.
     * @return array<string, mixed>
     * @throws JsonException - if it isn't valid JSON.
     * @throws RuntimeException - if it isn't a JSON object.
     */
    public static function decode(string $json) : array
    {
        return self::toObject(json_decode($json, true, 512, JSON_THROW_ON_ERROR), "the decoded JSON");
    }


    /**
     * Get the value at a path of keys, e.g. JsonLib::getValue($item, "rule", "comment") for $item["rule"]["comment"].
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return mixed
     * @throws RuntimeException - if there's nothing at that path.
     */
    public static function getValue(mixed $json, string|int ...$path) : mixed
    {
        $value = $json;

        foreach ($path as $key)
        {
            if (!is_array($value) || !array_key_exists($key, $value))
            {
                throw new RuntimeException("There's nothing at " . self::describePath(...$path) . " in the JSON.");
            }

            $value = $value[$key];
        }

        return $value;
    }


    /**
     * Check whether there's a value (other than null) at a path of keys, as isset() would.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return bool
     */
    public static function hasValue(mixed $json, string|int ...$path) : bool
    {
        $value = $json;

        foreach ($path as $key)
        {
            $value = is_array($value) ? ($value[$key] ?? null) : null;
        }

        return $value !== null;
    }


    /**
     * Get the JSON object at a path of keys.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return array<string, mixed>
     * @throws RuntimeException - if there's nothing there, or it isn't a JSON object.
     */
    public static function getObject(mixed $json, string|int ...$path) : array
    {
        return self::toObject(self::getValue($json, ...$path), self::describePath(...$path));
    }


    /**
     * Get the list of JSON objects at a path of keys, e.g. a rule's statements.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return list<array<string, mixed>>
     * @throws RuntimeException - if there's nothing there, or it isn't a list of JSON objects.
     */
    public static function getObjectList(mixed $json, string|int ...$path) : array
    {
        $objects = [];

        foreach (self::getList($json, ...$path) as $index => $value)
        {
            $objects[] = self::toObject($value, self::describePath(...$path, ...[$index]));
        }

        return $objects;
    }


    /**
     * Get the list of strings at a path of keys, e.g. a flowtable's devices.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return list<string>
     * @throws RuntimeException - if there's nothing there, or it isn't a list of strings.
     */
    public static function getStringList(mixed $json, string|int ...$path) : array
    {
        $strings = [];

        foreach (self::getList($json, ...$path) as $index => $value)
        {
            if (!is_string($value))
            {
                $where = self::describePath(...$path, ...[$index]);
                throw new RuntimeException("{$where} in the JSON is " . get_debug_type($value) . ", not a string.");
            }

            $strings[] = $value;
        }

        return $strings;
    }


    /**
     * Get the string at a path of keys.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return string
     * @throws RuntimeException - if there's nothing there, or it isn't a string.
     */
    public static function getString(mixed $json, string|int ...$path) : string
    {
        $value = self::getValue($json, ...$path);

        if (!is_string($value))
        {
            $where = self::describePath(...$path);
            throw new RuntimeException("{$where} in the JSON is " . get_debug_type($value) . ", not a string.");
        }

        return $value;
    }


    /**
     * Get the JSON list at a path of keys.
     * @param mixed $json - the JSON, or part of it.
     * @param string|int ...$path - the keys, outermost first.
     * @return list<mixed>
     * @throws RuntimeException - if there's nothing there, or it isn't a JSON list.
     */
    private static function getList(mixed $json, string|int ...$path) : array
    {
        $value = self::getValue($json, ...$path);

        if (!is_array($value) || !array_is_list($value))
        {
            $where = self::describePath(...$path);
            throw new RuntimeException("{$where} in the JSON is " . get_debug_type($value) . ", not a list.");
        }

        return $value;
    }


    /**
     * Check that a value is a JSON object (an array with string keys), and give it that type.
     * @param mixed $value - the value.
     * @param string $where - where it is, for the message.
     * @return array<string, mixed>
     * @throws RuntimeException - if it isn't a JSON object.
     */
    private static function toObject(mixed $value, string $where) : array
    {
        if (!is_array($value))
        {
            throw new RuntimeException("{$where} in the JSON is " . get_debug_type($value) . ", not an object.");
        }

        $object = [];

        foreach ($value as $key => $item)
        {
            if (!is_string($key))
            {
                throw new RuntimeException("{$where} in the JSON is a list, not an object.");
            }

            $object[$key] = $item;
        }

        return $object;
    }


    /**
     * Describe a path of keys, for messages, e.g. ["rule"]["comment"].
     * @param string|int ...$path - the keys, outermost first.
     * @return string
     */
    private static function describePath(string|int ...$path) : string
    {
        $parts = [];

        foreach ($path as $key)
        {
            $parts[] = is_int($key) ? "[{$key}]" : "[\"{$key}\"]";
        }

        return implode("", $parts);
    }
}
