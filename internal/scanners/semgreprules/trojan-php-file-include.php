<?php

function direct() {
    // ruleid: trojan-php-include-from-request
    include($_GET['page']);
}

function viaVariable() {
    $page = $_REQUEST["page"];
    // ruleid: trojan-php-include-from-request, trojan-php-include-variable-path
    require_once ($page);
}

function withSuffix() {
    $language = $_GET["language"] . ".php";
    // ruleid: trojan-php-include-from-request, trojan-php-include-variable-path
    include $language;
}

function safeBasename() {
    $page = basename($_GET['page']);
    // ok: trojan-php-include-from-request
    include __DIR__ . '/pages/' . $page;
}

// ok: trojan-php-include-from-request
include __DIR__ . '/config.php';

// ok: trojan-php-include-variable-path
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

// ok: trojan-php-include-variable-path
include 'header.php';

if (isset($file))
    // ruleid: trojan-php-include-variable-path
    include( $file );

foreach (glob(__DIR__ . '/plugins/*.php') as $plugin) {
    // ok: trojan-php-include-variable-path
    include $plugin;
}

$allowed = array('a.php', 'b.php');
if (in_array($lang, $allowed)) {
    // ok: trojan-php-include-variable-path
    include $lang;
}
