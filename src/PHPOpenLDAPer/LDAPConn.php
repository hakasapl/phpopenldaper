<?php

namespace PHPOpenLDAPer;
use LDAP\Connection;

/**
 * Class that represents a connection to an LDAP server
 *
 * Originally written for UMASS Amherst Research Computing
 *
 * @author Hakan Saplakoglu <hakansaplakog@gmail.com>
 * @version 1.0.0
 * @since 7.2.0
 */
class LDAPConn
{
    protected Connection $conn;  // LDAP link
    private array $entries = [];

  /**
   * Constructor, starts an ldap connection and binds to a DN
   */
    public function __construct(string $host, string $bind_dn, string $bind_pass)
    {
        $this->conn = ldap_connect($host);

        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_bind($this->conn, $bind_dn, $bind_pass);
    }

  /**
   * Get the connection instance of the LDAP link
   */
    public function getConn()
    {
        return $this->conn;
    }

  /**
   * Runs a search on the LDAP server and returns entries
   */
    // public function search(string $filter, string $base, array $attributes, bool $recursive = true)
    // {
    //     if ($recursive) {
    //         $search = ldap_search($this->conn, $base, $filter, $attributes);
    //     } else {
    //         $search = ldap_list($this->conn, $base, $filter, $attributes);
    //     }

    //     $search_entries = @ldap_get_entries($this->conn, $search);
    //     self::stripCount($search_entries);

    //     $output = array();
    //     for ($i = 0; isset($search_entries) && $i < count($search_entries); $i++) {
    //         array_push($output, new LDAPEntry($this->conn, $search_entries[$i]["dn"]));
    //     }

    //     return $output;
    // }

  /**
   * Gets a single entry from the LDAP server. If multiple calls are made for the same DN,
   * subsequent calls will return the same object as the first call.
   */
    public function getEntry(string $dn): LDAPEntry
    {
        if (array_key_exists($dn, $this->entries)) {
            return $this->entries[$dn];
        }
        $entry = new LDAPEntry($this->getConn(), $dn);
        $this->entries[$dn] = $entry;
        return $entry;
    }

  /**
   * Removes the very annoying "count" attribute that comes out of all ldap search queries (why does that exist? Every language I know can figure out the count itself)
   */
    public static function stripCount(&$arr)
    {
        if (is_array($arr)) {
            unset($arr['count']);
            array_walk($arr, [self::class, "stripCount"]);
        }
    }
}
