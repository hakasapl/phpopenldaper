<?php

namespace PHPOpenLDAPer;

use RuntimeException;

/**
 * Class that represents one entry in an LDAP server
 * This class is not meant to be constructed outside the ldapConn class
 *
 * Originally written for UMASS Amherst Research Computing
 *
 * @author Hakan Saplakoglu <hsaplakoglu@umass.edu>
 * @version 1.0.0
 * @since 7.2.0
 */
class LDAPEntry
{
    private $conn;  // LDAP connection link
    private $dn;  // Distinguished Name of the Entry

    private $object;  // Array containing the attributes of the entry as it looks on the server
    private $mods;  // Array containing modifications to $object array that have yet to be applied

  /**
   * Constructor that creates an ldapEntry object
   *
   * @param link_identifier $conn LDAP connection link from ldap_connect, ldap_bind must have already been used
   * @param string $dn Distinguished Name of the requested entry
   */
    public function __construct($conn, $dn)
    {
        $this->conn = $conn;
        $this->dn = $dn;
        $this->pullObject();
    }

  /**
   * Pulls an entry from the ldap connection, and sets $object If entry does not exist, $object = null.
   */
    private function pullObject()
    {
        $result = @ldap_read($this->conn, $this->dn, "(objectclass=*)");
        if ($result === false) {
            $this->object = null;
            return false;
        }
        $search = @ldap_get_entries($this->conn, $result);
        LDAPConn::stripCount($search);

        if (isset($search)) {
          // Object Exists
            if (count($search) > 1) {  // 1 For LDAP count element, and 1 for actual object
                // Duplicate Objects Found
                die("FATAL: Call to ldapObject with non-unique DN.");
            } else {
                $this->object = $search[0];
            }
        }
    }

  /**
   * Gets the Distinguished Name (DN) of the Entry
   *
   * @return string DN of the entry
   */
    public function getDN()
    {
        return $this->dn;
    }

  /**
   * Gets the Relative Distinguished Name (RDN) of the Entry
   *
   * @return string RDN of the entry
   */
    public function getRDN()
    {
        return substr($this->dn, 0, strpos($this->dn, ','));
    }

  /**
   * Checks whether entry exists on the LDAP server, modifications that haven't been applied don't count
   *
   * @return bool True if entry exists, False if it does not exist
   */
    public function exists()
    {
        return !is_null($this->object);
    }

    private function getLdapErrorInfo()
    {
        $diagMsg = "";
        ldap_get_option($this->conn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagMsg);
        return [
            "ldap_error" => ldap_error($this->conn),
            "LDAP_OPT_DIAGNOSTIC_MESSAGE" => $diagMsg,
            "errno" => ldap_errno($this->conn),
            "error_get_last" => error_get_last()
        ];
    }

  /**
   * Writes changes set in $mods array to the LDAP entry on the server.
   *
   * @return void
   * @throws RuntimeException if ldap_add / ldap_mod_replace fails
   */
    public function write()
    {
        if ($this->mods == null) {
            return;
        }
        if ($this->object == null) {
            $funcName = "ldap_add";
            ldap_add($this->conn, $this->dn, $this->mods);
        } else {
            $funcName = "ldap_mod_replace";
            ldap_mod_replace($this->conn, $this->dn, $this->mods);
        }
        $errorInfo = $this->getLdapErrorInfo();
        if ($errorInfo["errno"] != 0) {
            $errorInfo["func"] = $funcName;
            $errorInfo["mods"] = $this->mods;
            throw new RuntimeException("LDAP error!\n" . json_encode($errorInfo, JSON_PRETTY_PRINT));
        }
        $this->pullObject();  // Refresh $object array
        $this->mods = null;  // Reset Modifications Array to Null
    }

  /**
   * Deletes the entry (no need to call write())
   *
   * @return void
   * @throws RuntimeException if ldap_delete fails
   */
    public function delete()
    {
        if ($this->object == null) {
            return;
        }
        ldap_delete($this->conn, $this->dn);
        $errorInfo = $this->getLdapErrorInfo();
        if ($errorInfo["errno"] != 0) {
            throw new RuntimeException("LDAP error!\n" . json_encode($errorInfo, JSON_PRETTY_PRINT));
        }
    }

  /**
   * Moves the entry to a new location
   *
   * @param string $destination Destination CN to move this entry
   * @return mixed ldapEntry of the new entry if successful, false on failure
   */
    public function move($destination)
    {
        $newRDN = substr($destination, 0, strpos($destination, ','));
        $newParent = substr($destination, strpos($destination, ',') + 1);
        if (ldap_rename($this->conn, $this->dn, $newRDN, $newParent, true)) {
            $this->pullObject();  // Refresh the existing entry
            return new LDAPEntry($this->conn, $destination);
        } else {
            return false;
        }
    }

  /**
   * Gets the immediate parent of the entry
   *
   * @return ldapEntry The parent of the current Entry
   */
    public function getParent()
    {
        return new LDAPEntry($this->conn, substr($this->dn, strpos($this->dn, ',') + 1)); //TODO edge case for parent being non-existent (part of base dn)
    }

  /**
   * Gets an array of children of the entry
   *
   * @param boolean $recursive (optional) If true, recursive search. Default is false.
   * @param string $filter (optional) Filter matching LDAP search filter syntax
   * @return array Array of children entries
   */
    public function getChildrenArray($recursive = false, $filter = "(objectclass=*)")
    {
        if ($recursive) {
            $search = ldap_search($this->conn, $this->dn, $filter);
        } else {
            $search = ldap_list($this->conn, $this->dn, $filter);
        }

        $search_entries = @ldap_get_entries($this->conn, $search);
        LDAPConn::stripCount($search_entries);

        if (count($search_entries) > 0 && $search_entries[0]["dn"] == $this->getDN()) {
            array_shift($search_entries);
        }

        return $search_entries;
    }

  /**
   * Gets an array of the children of the entry saved as ldapEntry class
   *
   * @param bool $recursive (optional) If true, recursive search. Default is false.
   * @param string $filter (optional) Filter matching LDAP search filter syntax
   * @return array Array of children ldapEntry objects
   */
    public function getChildren($recursive = false, $filter = "(objectclass=*)")
    {
        $children_array = $this->getChildrenArray($recursive, $filter);

        $output = array();
        foreach ($children_array as $child) {
            array_push($output, new LDAPEntry($this->conn, $child["dn"]));
        }

        return $output;
    }

  /**
   * Gets a single child using RDN
   *
   * @param string $rdn RDN of requested child
   * @return ldapEntry object of the child
   */
    public function getChild($rdn)
    {
        return new LDAPEntry($this->conn, $rdn . "," . $this->dn);
    }

  /**
   * Checks if entry has any children
   *
   * @return boolean True if yes, False if no
   */
    public function hasChildren()
    {
        return count($this->getChildrenArray()) > 0;
    }

  /**
   * Gets the number of children of the entry
   *
   * @param boolean $recursive (optional) If true, recursive search. Default is false.
   * @return int Number of children of entry
   */
    public function numChildren($recursive = false)
    {
        return count($this->getChildrenArray($recursive));
    }

  /**
   * Sets the value of a single attribute in the LDAP object (This will overwrite any existing values in the attribute)
   *
   * @param string $attr Attribute Key Name to modify
   * @param mixed $value array or string value to set the attribute value to
   */
    public function setAttribute($attr, $value)
    {
        if (is_array($value)) {
            $this->mods[$attr] = $value;
        } else {
            $this->mods[$attr] = array($value);
        }
    }

  /**
   * Appends values to a given attribute, preserving initial values in the attribute
   *
   * @param string $attr Attribute Key Name to modify
   * @param mixed $value array or string value to append attribute
   */
    public function appendAttribute($attr, $value)
    {
        $objArr = array();
        if (isset($this->object[$attr])) {
            $objArr = $this->object[$attr];
        }

        $modArr = array();
        if (isset($this->mods[$attr])) {
            $modArr = $this->mods[$attr];
        }

        if (is_array($value)) {
            $this->mods[$attr] = array_merge($objArr, $modArr, $value);
        } else {
            $this->mods[$attr] = array_merge($objArr, $modArr, (array) $value);
        }
    }

  /**
   * Sets and overwrites attributes based on a single array.
   *
   * @param array $arr Array of keys and attributes. Key values must be attribute key
   */
    public function setAttributes($arr)
    {
        $this->mods = $arr;
    }

  /**
   * Appends attributes based on a single array
   *
   * @param array $arr Array of keys and attributes. Key values must be attribute key
   */
    public function appendAttributes($arr)
    {
        foreach ($arr as $attr) {
            $this->appendAttribute(key($attr), $attr);
        }
    }

  /**
   * Removes a attribute
   *
   * @param string $attr Key of attribute to be removed
   */
    public function removeAttribute($attr, $item = null)
    {
        $this->mods[$attr] = array();
    }

  /**
   * Removes values of an attribute
   *
   * @param string $attr Attribute to modify
   * @param string $value Value to erase from attribute
   */
    public function removeAttributeEntryByValue($attr, $value)
    {
        $arr = $this->object[$attr];
        for ($i = 0; $i < count($arr); $i++) {
            if ($arr[$i] == $value) {
                unset($arr[$i]);
            }
        }
        $this->mods[$attr] = array_values($arr);
    }

  /**
   * Returns a given attribute of the object
   *
   * @param string $attr Attribute key value to return
   * @return array value of requested attribute. Note: lots of attributes are arrays by default, so you have to use index 0 of the return value to get a single value
   */
    public function getAttribute($attr)
    {
        if (!$this->exists()) {
            throw new RuntimeException("nonexistent entry has no attributes");
        }
        if (isset($this->object[$attr])) {
            return $this->object[$attr];
        } else {
            return [];
        }
    }

  /**
   * Returns the entire objects attributes in form suitable for setAttributes()
   *
   * @return array Array where keys are attributes
   */
    public function getAttributes()
    {
        if (!$this->exists()) {
            throw new RuntimeException("nonexistent entry has no attributes");
        }
        $output = [];
        foreach ($this->object as $key => $val) {
            if (preg_match("/^[0-9]+$/", $key)) {
                continue;
            }
            if ($key == "dn") {
                continue;
            }
            $output[$key] = $val;
        }
        return $output;
    }

  /**
   * Checks if entry has an attribute
   *
   * @param string $attr Attribute to check
   * @return bool true if attribute exists in entry, false otherwise
   */
    public function hasAttribute($attr)
    {
        if ($this->exists()) {
            return array_key_exists($attr, $this->object);
        } else {
            return false;
        }
    }

  /**
   * Checks if an attribute value exists within an attribute
   *
   * @param string $attr Attribute to check
   * @param string $value Value to check
   * @return bool true if value exists in attribute, false otherwise
   */
    public function attributeValueExists($attr, $value)
    {
        return in_array($value, $this->getAttribute($attr));
    }

  /**
   * Check if there are pending changes
   *
   * @return bool true is there are pending changes, false otherwise
   */
    public function pendingChanges()
    {
        return !is_null($this->mods);
    }
}
