<?php
$i = 1;

$scheme = 'http';

if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    $scheme = (string) $_SERVER['HTTP_X_FORWARDED_PROTO'];
} elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    $scheme = 'https';
}

$host = $_SERVER['HTTP_HOST'] ?? 'phpmyadmin.localhost.com';
$cfg['PmaAbsoluteUri'] = sprintf('%s://%s/', $scheme, $host);
$cfg['ThemeDefault'] = 'pmahomme';
$cfg['ThemeManager'] = false;

/* Server */
$cfg['Servers'][$i]['host'] = 'mariadb';
$cfg['Servers'][$i]['port'] = 3306;

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
