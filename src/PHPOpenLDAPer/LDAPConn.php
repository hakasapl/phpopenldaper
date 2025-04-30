<?php

namespace PHPOpenLDAPer;

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
    protected $conn;  // LDAP link
    private $entries = [];

  /**
   * Constructor, starts an ldap connection and binds to a DN
   *
   * @param string $host Host ldap address of server
   * @param string $bind_dn Admin bind dn
   * @param string $bind_pass Admin bind pass
   */
    public function __construct($host, $bind_dn, $bind_pass)
    {
        $this->conn = ldap_connect($host);

        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_bind($this->conn, $bind_dn, $bind_pass);
    }

  /**
   * Get the connection instance of the LDAP link
   *
   * @return link_identifier LDAP connection link
   */
    public function getConn()
    {
        return $this->conn;
    }

  /**
   * Runs a search on the LDAP server and returns entries
   *
   * @param string $filter LDAP_search filter
   * @param string $base Search base
   * @return array Array of ldapEntry objects
   */
    public function search($filter, $base, $recursive = true)
    {
        if ($recursive) {
            $search = ldap_search($this->conn, $base, $filter);
        } else {
            $search = ldap_list($this->conn, $base, $filter);
        }

        $search_entries = @ldap_get_entries($this->conn, $search);
        self::stripCount($search_entries);

        $output = array();
        for ($i = 0; isset($search_entries) && $i < count($search_entries); $i++) {
            array_push($output, new LDAPEntry($this->conn, $search_entries[$i]["dn"]));
        }

        return $output;
    }

  /**
   * Gets a single entry from the LDAP server. If multiple calls are made for the same DN,
   * subsequent calls will return the same object as the first call.
   *
   * @param string $dn Distinguished name (DN) of requested entry
   * @return ldapEntry requested entry object
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
   *
   * @param array $arr Array passed by reference to modify
   */
    public static function stripCount(&$arr)
    {
        if (is_array($arr)) {
            unset($arr['count']);
            array_walk($arr, [self::class, "stripCount"]);
        }
    }
}
