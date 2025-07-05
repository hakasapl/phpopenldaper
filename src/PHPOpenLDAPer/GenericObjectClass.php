<?php

namespace PHPOpenLDAPer;

/**
 * Class that represents an LDAP entry with specific attributes
 * Uses property-hooks for ease of access
 *
 * Originally written for UMass Amherst Research Computing & Data
 *
 * @author Simon Leary <simonleary42@proton.me>
 * @version 1.0.0
 * @since 8.4.0
 */
class GenericObjectClass extends LDAPEntry
{
    public string $cn {
        get => $this->getAttribute("cn")[0]
    }
    public string $dn {
        get => $this->getAttribute("dn")[0]
    }
    public array $objectClass {
        get => $this->getAttribute("objectClass")
    }
}
