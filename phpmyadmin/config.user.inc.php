<?php
$i = 1;

$scheme = 'http';

if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    $scheme = (string) $_SERVER['HTTP_X_FORWARDED_PROTO'];
    if (strtolower($scheme) === 'https') {
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['SERVER_PORT'] = '443';
    }
} elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    $scheme = 'https';
}

$host = $_SERVER['HTTP_HOST'] ?? 'phpmyadmin.localhost.com';
$prefix = '';
if (!empty($_SERVER['HTTP_X_FORWARDED_PREFIX'])) {
    $prefix = '/' . trim((string) $_SERVER['HTTP_X_FORWARDED_PREFIX'], '/');
}
$cfg['PmaAbsoluteUri'] = sprintf('%s://%s%s/', $scheme, $host, $prefix);
$cfg['ThemeDefault'] = 'pmahomme';
$cfg['ThemeManager'] = false;

$requestedDb = '';
if (!empty($_GET['db']) && is_string($_GET['db'])) {
    $requestedDb = (string) $_GET['db'];
} elseif (!empty($_POST['db']) && is_string($_POST['db'])) {
    $requestedDb = (string) $_POST['db'];
}

if ($requestedDb !== '' && preg_match('/^[A-Za-z0-9_]+$/', $requestedDb) === 1) {
    $cfg['Servers'][$i]['only_db'] = [$requestedDb];
    $cfg['NavigationTreeEnableGrouping'] = false;
    $cfg['ShowDatabasesNavigationAsTree'] = false;
}

/* Server */
$cfg['Servers'][$i]['host'] = getenv('PMA_HOST') ?: 'mariadb';
$cfg['Servers'][$i]['port'] = (int) (getenv('PMA_PORT') ?: 3306);

/* Configuration storage (pmadb) */
$controlPasswordFile = getenv('PMA_CONTROL_PASSWORD_FILE') ?: '/run/secrets/phpmyadmin_control_password';
if (is_readable($controlPasswordFile)) {
    $controlPassword = trim((string) file_get_contents($controlPasswordFile));
    if ($controlPassword !== '') {
        $cfg['Servers'][$i]['controluser'] = 'pma';
        $cfg['Servers'][$i]['controlpass'] = $controlPassword;
        $cfg['Servers'][$i]['pmadb'] = 'phpmyadmin';
    }
}

/* TLS to MariaDB with verification */
$cfg['Servers'][$i]['ssl'] = true;
$cfg['Servers'][$i]['ssl_ca'] = '/etc/phpmyadmin/certs/ca.pem';
$cfg['Servers'][$i]['ssl_verify'] = true;
