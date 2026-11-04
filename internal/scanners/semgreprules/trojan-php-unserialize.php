<?php

function fromCookie() {
    // ruleid: trojan-php-unserialize-request
    $prefs = unserialize(base64_decode($_COOKIE['prefs']));
}

function fromGet() {
    $data = $_GET['d'];
    // ruleid: trojan-php-unserialize-request
    $obj = unserialize($data);
}

function allowedClassesOff() {
    // ok: trojan-php-unserialize-request
    $obj = unserialize($_POST['d'], ['allowed_classes' => false]);
}

function fromCache($s) {
    // ok: trojan-php-unserialize-request
    return unserialize($s);
}
