<?php

class SQLQueryHandler {
    public function getBlogRecord($pBloggerName) {
        // ruleid: trojan-php-sql-from-function-input
        $lQueryString = "
            SELECT * FROM blogs_table
            WHERE blogger_name like '{$pBloggerName}%'
            ORDER BY date DESC";
        return $this->mMySQLHandler->executeQuery($lQueryString);
    }

    public function insertBlogRecord($pBloggerName, $pBlogEntry) {
        // ruleid: trojan-php-sql-from-function-input
        $lQueryString = "INSERT INTO blogs_table(blogger_name, comment) VALUES ('" .
            $pBloggerName . "', '" .
            $pBlogEntry . "')";
        return $this->mMySQLHandler->executeQuery($lQueryString);
    }

    public function getPenTestTool($pPostedToolID) {
        // ruleid: trojan-php-sql-from-function-input
        $lWhereClause = " WHERE tool_id = '" . $pPostedToolID . "';";
        // ruleid: trojan-php-sql-from-function-input
        $lQueryString = "SELECT tool_id FROM pen_test_tools" . $lWhereClause;
        return $this->mMySQLHandler->executeQuery($lQueryString);
    }

    public function getById(int $pID) {
        // ok: trojan-php-sql-from-function-input
        $q = "SELECT * FROM t WHERE id = " . $pID;
        return $this->db->query($q);
    }

    public function escaped($pName) {
        $name = $this->db->real_escape_string($pName);
        // ok: trojan-php-sql-from-function-input
        $q = "SELECT * FROM t WHERE name = '" . $name . "'";
        return $this->db->query($q);
    }

    public function prepared($pName) {
        // ok: trojan-php-sql-from-function-input
        $stmt = $this->db->prepare("SELECT * FROM t WHERE name = ?");
        $stmt->bind_param("s", $pName);
        return $stmt->execute();
    }
}

function lookup($id) {
    // ruleid: trojan-php-sql-from-function-input
    $result = mysqli_query($GLOBALS['conn'], "SELECT first_name FROM users WHERE user_id = '$id';");
}

function message($name) {
    // ok: trojan-php-sql-from-function-input
    echo "Hello " . $name . ", select a file from the list";
}

function note($name) {
    // ok: trojan-php-sql-from-function-input
    $msg = "Please select a file from " . $name;
}

function debugQuery($q) {
    // ok: trojan-php-sql-from-function-input
    echo "Query: SELECT * FROM t WHERE x = " . $q;
}

function intCast($id) {
    // ok: trojan-php-sql-from-function-input
    $q = "SELECT * FROM t WHERE id = " . (int) $id;
}

function intvalInline($id) {
    // ok: trojan-php-sql-from-function-input
    $q = "SELECT * FROM t WHERE id = " . intval($id);
}

function intCastAssigned($raw) {
    $id = (int) $raw;
    // ok: trojan-php-sql-from-function-input
    $q = "SELECT * FROM t WHERE id = " . $id;
    return $q;
}

function boolCastAssigned($raw) {
    $active = (bool) $raw;
    // ok: trojan-php-sql-from-function-input
    $q = "SELECT * FROM t WHERE active = " . $active;
    return $q;
}
