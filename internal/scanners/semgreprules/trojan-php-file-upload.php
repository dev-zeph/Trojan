<?php

function low() {
    $target_path  = "hackable/uploads/";
    $target_path .= basename($_FILES['uploaded']['name']);
    // ruleid: trojan-php-upload-client-filename
    if (!move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
        echo "fail";
    }
}

function inline() {
    // ruleid: trojan-php-upload-client-filename
    move_uploaded_file($_FILES["file"]["tmp_name"], "images/" . $_FILES["file"]["name"]);
}

function viaName() {
    $name = $_FILES['doc']['name'];
    $dest = __DIR__ . '/uploads/' . $name;
    // ruleid: trojan-php-upload-client-filename
    move_uploaded_file($_FILES['doc']['tmp_name'], $dest);
}

function generatedName() {
    $ext = 'png';
    $dest = 'uploads/' . md5(uniqid() . $_FILES['uploaded']['name']) . '.' . $ext;
    // ok: trojan-php-upload-client-filename
    move_uploaded_file($_FILES['uploaded']['tmp_name'], $dest);
}

function randomName() {
    // ok: trojan-php-upload-client-filename
    move_uploaded_file($_FILES['uploaded']['tmp_name'], 'uploads/' . bin2hex(random_bytes(16)) . '.png');
}
