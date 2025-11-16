<?php

namespace PHPOpenLDAPer;

use ValueError;
use RuntimeException;
use LDAP\Connection;

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
    private Connection $conn;  // LDAP connection link
    private string $dn;  // Distinguished Name of the Entry

    private ?array $object;  // Array containing the attributes of the entry as it looks on the server
    private ?array $mods;  // Array containing modifications to $object array that have yet to be applied

  /**
   * Constructor that creates an ldapEntry object
   */
    public function __construct(Connection $conn, string $dn)
    {
        $this->conn = $conn;
        $this->dn = $dn;
        $this->pullObject();
    }

  /**
   * Pulls an entry from the ldap connection, and sets $object If entry does not exist, $object = null.
   * @returns bool existence of ldap object
   */
    private function pullObject(): bool
    {
        $result = @ldap_read($this->conn, $this->dn, "(objectclass=*)");
        if ($result === false) {
            $this->object = null;
            return false;
        }
        $entries = @ldap_get_entries($this->conn, $result);
        if ($entries === false) {
            $this->object = null;
            return false;
        }
        LDAPConn::stripCount($entries);
        if (count($entries) > 1) {
            throw new \Exception("FATAL: Call to ldapObject with non-unique DN.");
        } else {
            $this->object = $entries[0];
            return true;
        }
    }

  /**
   * Gets the Distinguished Name (DN) of the Entry
   *
   * @return string DN of the entry
   */
    public function getDN(): string
    {
        return $this->dn;
    }

  /**
   * Gets the Relative Distinguished Name (RDN) of the Entry
   *
   * @return string RDN of the entry
   */
    public function getRDN(): string
    {
        return substr($this->dn, 0, strpos($this->dn, ','));
    }

  /**
   * Checks whether entry exists on the LDAP server, modifications that haven't been applied don't count
   *
   * @return bool True if entry exists, False if it does not exist
   */
    public function exists(): bool
    {
        return !is_null($this->object);
    }

    public function ensureExists(): void
    {
        if (!$this->exists()) {
            throw new RuntimeException("I do not exist! ($this->dn)");
        }
    }

    private function getLdapErrorInfo(): array
    {
        $diagMsg = "";
        ldap_get_option($this->conn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagMsg);
        return [
            "ldap_error" => ldap_error($this->conn),
            "LDAP_OPT_DIAGNOSTIC_MESSAGE" => $diagMsg,
            "ldap_errno" => ldap_errno($this->conn),
            "error_get_last" => error_get_last()
        ];
    }

  /**
   * Writes changes set in $mods array to the LDAP entry on the server.
   *
   * @return void
   * @throws RuntimeException if ldap_add / ldap_mod_replace fails
   */
    public function write(): void
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
        if ($errorInfo["ldap_errno"] != 0) {
            $errorInfo["func"] = $funcName;
            $errorInfo["mods"] = $this->mods;
            $errorInfoStr = json_encode($errorInfo, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            throw new RuntimeException("LDAP error!\n$errorInfoStr");
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
    public function delete(): void
    {
        if ($this->object == null) {
            return;
        }
        ldap_delete($this->conn, $this->dn);
        $errorInfo = $this->getLdapErrorInfo();
        if ($errorInfo["ldap_errno"] != 0) {
            $errorInfoStr = json_encode($errorInfo, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            throw new RuntimeException("LDAP error!\n$errorInfoStr");
        }
        $this->mods = null;
        $this->pullObject();
    }

  /**
   * Moves the entry to a new location
   *
   * @param string $destination Destination CN to move this entry
   * @return mixed ldapEntry of the new entry if successful, false on failure
   */
    public function move(string $destination): bool|LDAPEntry
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
    public function getParent(): LDAPEntry
    {
        return new LDAPEntry($this->conn, substr($this->dn, strpos($this->dn, ',') + 1)); //TODO edge case for parent being non-existent (part of base dn)
    }

  /**
   * Gets an array of children of the entry
   *
   * @param array $attributes Requested attributes. Use `[]` to fetch all attributes.
   * @param boolean $recursive (optional) If true, recursive search. Default is false.
   * @param string $filter (optional) Filter matching LDAP search filter syntax
   * @return array Array of children entries
   */
    public function getChildrenArray(array $attributes, bool $recursive = false, string $filter = "(objectclass=*)"): array|bool
    {
        $attributes = array_map("strtolower", $attributes);
        if ($recursive) {
            $search = ldap_search($this->conn, $this->dn, $filter, $attributes);
        } else {
            $search = ldap_list($this->conn, $this->dn, $filter, $attributes);
        }

        $search_entries = @ldap_get_entries($this->conn, $search);
        LDAPConn::stripCount($search_entries);

        if (count($search_entries) > 0 && $search_entries[0]["dn"] == $this->getDN()) {
            array_shift($search_entries);
        }

        return $search_entries;
    }

 /**
   * Gets an array of children of the entry, but raises an error if expected attributes are not found
   *
   * @param array $attributes Requested attributes. Must have at least one element.
   * @param boolean $recursive (optional) If true, recursive search. Default is false.
   * @param string $filter (optional) Filter matching LDAP search filter syntax
   * @param array $default_values Keys are attribute names and values are default values.
   * attributes without any default value must exist in every single entry
   * or else a @throws RuntimeException will be thrown.
   * @return array Array of children entries
   */
    public function getChildrenArrayStrict(
        array $attributes,
        bool $recursive = false,
        string $filter = "(objectclass=*)",
        array $default_values = [],
    ): array {
        if (empty($attributes)) {
            throw new ValueError('$attributes cannot be empty. use non-strict version instead.');
        }
        $attributes = array_map("strtolower", $attributes);
        $default_values = array_change_key_case($default_values, CASE_LOWER);
        $attributes_require_exists = array_diff($attributes, array_keys($default_values));
        $output = $this->getChildrenArray($attributes, $recursive, $filter);
        foreach ($output as $i => $entry) {
            foreach ($default_values as $attribute_name => $default_value) {
                if (!array_key_exists($attribute_name, $entry)) {
                    $output[$i][$attribute_name] = $default_value;
                }
            }
            foreach ($attributes_require_exists as $attribute_name) {
                if (!array_key_exists($attribute_name, $entry)) {
                    $dn = $entry["dn"];
                    throw new RuntimeException(
                        "entry '$dn' does not have attribute '$attribute_name'",
                    );
                }
            }
        }
        return $output;
    }

  /**
   * Gets an array of the children of the entry saved as ldapEntry class
   *
   * @param bool $recursive (optional) If true, recursive search. Default is false.
   * @param string $filter (optional) Filter matching LDAP search filter syntax
   * @return array Array of children ldapEntry objects
   */
    public function getChildren(bool $recursive = false, string $filter = "(objectclass=*)"): array
    {
        $children_array = $this->getChildrenArray(["dn"], $recursive, $filter);

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
    public function getChild(string $rdn): LDAPEntry
    {
        return new LDAPEntry($this->conn, $rdn . "," . $this->dn);
    }

  /**
   * Checks if entry has any children
   *
   * @return boolean True if yes, False if no
   */
    public function hasChildren(): bool
    {
        return count($this->getChildrenArray([])) > 0; // FIXME this is fetching all attributes
    }

  /**
   * Gets the number of children of the entry
   *
   * @param boolean $recursive (optional) If true, recursive search. Default is false.
   * @return int Number of children of entry
   */
    public function numChildren(bool $recursive = false): int
    {
        return count($this->getChildrenArray([], $recursive)); // FIXME this is fetching all attributes
    }

  /**
   * Sets the value of a single attribute in the LDAP object (This will overwrite any existing values in the attribute)
   *
   * @param string $attr Attribute Key Name to modify
   * @param mixed $value array or string value to set the attribute value to
   */
    public function setAttribute(string $attr, mixed $value): void
    {
        $attr = strtolower($attr);
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
    public function appendAttribute(string $attr, mixed $value): void
    {
        $attr = strtolower($attr);
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
    public function setAttributes(array $arr): void
    {
        $arr = array_change_key_case($arr, CASE_LOWER);
        $this->mods = $arr;
    }

  /**
   * Appends attributes based on a single array
   *
   * @param array $arr Array of keys and attributes. Key values must be attribute key
   */
    public function appendAttributes(array $arr): void
    {
        $arr = array_change_key_case($arr, CASE_LOWER);
        foreach ($arr as $attr) {
            $this->appendAttribute(strtolower(key($attr)), $attr);
        }
    }

  /**
   * Removes a attribute
   *
   * @param string $attr Key of attribute to be removed
   */
    public function removeAttribute(string $attr, $item = null): void
    {
        $attr = strtolower($attr);
        $this->mods[$attr] = array();
    }

  /**
   * Removes values of an attribute
   *
   * @param string $attr Attribute to modify
   * @param string $value Value to erase from attribute
   */
    public function removeAttributeEntryByValue(string $attr, mixed $value): void
    {
        $attr = strtolower($attr);
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
   * @return array value of requested attribute.
   */
    public function getAttribute(string $attr): mixed
    {
        $attr = strtolower($attr);
        if (!$this->exists()) {
            throw new RuntimeException("cannot get attribute from nonexistent entry");
        }
        if (isset($this->object[$attr])) {
            return is_array($this->object[$attr]) ? $this->object[$attr] : [$this->object[$attr]];
        } else {
            return [];
        }
    }

  /**
   * Returns the entire objects attributes in form suitable for setAttributes()
   *
   * @return array Array where keys are attributes
   */
    public function getAttributes(): array
    {
        if (!$this->exists()) {
            throw new RuntimeException("cannot get attributes from nonexistent entry");
        }
        $output = [];
        foreach ($this->object as $key => $val) {
            if (preg_match("/^[0-9]+$/", $key)) {
                continue;
            }
            $key = strtolower($key);
            $output[$key] = is_array($val) ? $val : [$val];
        }
        return $output;
    }

  /**
   * Checks if entry has an attribute
   *
   * @param string $attr Attribute to check
   * @return bool true if attribute exists in entry, false otherwise
   */
    public function hasAttribute(string $attr): bool
    {
        $attr = strtolower($attr);
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
    public function attributeValueExists(string $attr, mixed $value): bool
    {
        $attr = strtolower($attr);
        return in_array($value, $this->getAttribute($attr));
    }

  /**
   * Check if there are pending changes
   *
   * @return bool true is there are pending changes, false otherwise
   */
    public function pendingChanges(): bool
    {
        return !is_null($this->mods);
    }
}
