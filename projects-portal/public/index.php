<?php
declare(strict_types=1);

http_response_code(503);
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

echo "Stexor Control Center is served by the Node control-center service.\n";
echo "Open https://projects.localhost.com/ through Traefik/project-router.\n";
