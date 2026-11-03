<?php

function rawBody() {
    $body = file_get_contents("php://input");
    // ruleid: trojan-php-xxe-request-xml
    $xml = simplexml_load_string($body);
}

function fromPost() {
    $doc = new DOMDocument();
    // ruleid: trojan-php-xxe-request-xml
    $doc->loadXML($_POST['xml']);
}

function guarded() {
    $body = file_get_contents("php://input");
    libxml_disable_entity_loader(true);
    // ok: trojan-php-xxe-request-xml
    $xml = simplexml_load_string($body);
}

function noNet() {
    // ok: trojan-php-xxe-request-xml
    $xml = simplexml_load_string($_POST['x'], 'SimpleXMLElement', LIBXML_NONET);
}

function fixedFile() {
    // ok: trojan-php-xxe-request-xml, trojan-php-xxe-entities-enabled
    $xml = simplexml_load_file("passwords/heroes.xml");
}

function validator($lXML) {
    // ruleid: trojan-php-xxe-entities-enabled
    libxml_disable_entity_loader(false);
    $d = new DOMDocument();
    // ruleid: trojan-php-xxe-entities-enabled
    $d->resolveExternals = true;
    // ruleid: trojan-php-xxe-entities-enabled
    $d->substituteEntities = true;
    $d->loadXML($lXML);
}

function noent($x) {
    $d = new DOMDocument();
    // ruleid: trojan-php-xxe-entities-enabled
    $d->loadXML($x, LIBXML_NOENT | LIBXML_DTDLOAD);
}
