<?php

namespace PHPOpenLDAPer;

use Exception;

/**
 * Represents an LDAPEntry with specific attributes
 * Uses magic __get method to return getAttribute($x) or getAttribute($x)[0]
 * After PHP 8.4 upgrade, property hooks should be used instead
 *
 * Originally written for Umass Amherst Research Computing & Data
 *
 * @author Simon Leary <simon.leary42@proton.me>
 * @version 1.0.0
 * @since 8.3.0
 */
class ObjectClass extends LDAPEntry
{
    protected static array $attributes_array = [];
    protected static array $attributes_non_array = [];

    public function __get(string $property): mixed {
        $property = strtolower($property);
        if (in_array($property, static::$attributes_array, true)) {
            return $this->getAttribute($property);
        }
        if (in_array($property, static::$attributes_non_array, true)) {
            $attribute = $this->getAttribute($property);
            if (empty($attribute)) {
                throw new AttributeNotFound($property);
            }
            return $attribute[0];
        }
        throw new Exception("Unknown property '$property'");
    }

    public function __isset(string $property): bool
    {
        $property = strtolower($property);
        if (
            in_array($property, static::$attributes_array, true)
            || in_array($property, static::$attributes_non_array, true)
        ) {
            return (!empty($this->getAttribute($property)));
        }
        return false;
    }
}
