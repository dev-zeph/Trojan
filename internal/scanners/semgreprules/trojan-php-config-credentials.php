<?php
define('DB_HOST', '127.0.0.1');
define('DB_USERNAME', 'root');
// ruleid: trojan-php-hardcoded-secret-constant
define('DB_PASSWORD', 'mutillidae');
// ruleid: trojan-php-hardcoded-secret-constant
define('JWT_SECRET_KEY', getenv('JWT_SECRET_KEY') ?: 'snowman');
// ok: trojan-php-hardcoded-secret-constant
define('DB_PASSWORD', '');
// ok: trojan-php-hardcoded-secret-constant
define('API_KEY', 'your-api-key');
// ok: trojan-php-hardcoded-secret-constant
define('AUTH_KEY', 'put your unique phrase here');
// ok: trojan-php-hardcoded-secret-constant
define('DB_PASSWORD', getenv('DB_PASSWORD'));

$db_server = "localhost";
$db_username = "root";
// ok: trojan-php-hardcoded-db-password
$db_password = "";
// ruleid: trojan-php-hardcoded-db-password
$db_password = 'S3cr3t!';
// ruleid: trojan-php-hardcoded-db-password
$_DVWA[ 'db_password' ] = getenv('DB_PASSWORD') ?: 'p@ssw0rd';
// ok: trojan-php-hardcoded-db-password
$password = $db_password;
// ok: trojan-php-hardcoded-db-password
$db_password = getenv('DB_PASSWORD');
// ok: trojan-php-hardcoded-db-password
$db_pass = 'changeme';
// ok: trojan-php-hardcoded-db-password
$password = "<password>";
