<?php
declare(strict_types=1);

$docsRoot = '/var/www/infra-docs';
$projectRoots = [
    'Mounted source' => '/var/www/projects',
    'Project source' => '/project',
];

$docs = [
    'Start Here' => [
        ['README.md', 'Overview and local usage'],
        ['RUNBOOK.md', 'Operations runbook'],
        ['VPS-PREDEPLOY-CHECKLIST.md', 'VPS pre-deploy checklist'],
    ],
    'Security And Readiness' => [
        ['SECURITY.md', 'Security model'],
        ['THREAT-MODEL.md', 'Threat model'],
        ['ENTERPRISE-MATURITY.md', 'Enterprise maturity matrix'],
        ['READINESS-REPORT.md', 'Readiness report'],
        ['FINAL-READINESS-AUDIT.md', 'Final audit notes'],
    ],
    'Cloud And Edge' => [
        ['cloudflare/README.md', 'Cloudflare setup'],
        ['cloudflare/LIVE-CHANGES.md', 'Cloudflare live change log'],
    ],
];

$docMap = [];
foreach ($docs as $groupDocs) {
    foreach ($groupDocs as [$path]) {
        $docMap[$path] = true;
    }
}

$selectedDoc = $_GET['doc'] ?? '';
if (is_string($selectedDoc) && isset($docMap[$selectedDoc])) {
    renderDocument($docsRoot, $selectedDoc);
    exit;
}

renderIndex($docsRoot, $docs, discoverProjects($projectRoots, parseNodeProjectHosts()));

function renderIndex(string $docsRoot, array $docs, array $projects): void
{
    $phpProjects = projectsByType($projects, 'PHP');
    $nodeProjects = projectsByType($projects, 'Node');
    $toolLinks = [
        ['phpMyAdmin', 'https://phpmyadmin.localhost.com/', 'Database administration'],
        ['Keycloak', 'https://auth.localhost.com/', 'Identity provider'],
        ['Grafana', 'https://grafana.localhost.com/', 'Dashboards and metrics'],
        ['MinIO', 'https://minio.localhost.com/', 'Object storage console'],
    ];

    pageStart('Infrastructure Documentation');
    ?>
    <main class="shell">
        <section class="hero">
            <div>
                <p class="eyebrow">Local infrastructure</p>
                <h1>Projects dashboard</h1>
                <p class="lede">All mounted local projects are grouped by runtime and linked through their local HTTPS hostnames.</p>
            </div>
            <div class="status-grid" aria-label="Local status">
                <div><span><?= count($projects) ?></span><small>projects</small></div>
                <div><span><?= count($phpProjects) ?></span><small>php</small></div>
                <div><span><?= count($nodeProjects) ?></span><small>node</small></div>
            </div>
        </section>

        <section class="grid two project-grid">
            <div class="panel">
                <div class="panel-head">
                    <span>PHP</span>
                    <div>
                        <h2>PHP projects</h2>
                        <p><?= count($phpProjects) ?> local hosts via Apache</p>
                    </div>
                </div>
                <?php renderProjectCards($phpProjects, 'No PHP projects found in the mounted source directory.'); ?>
            </div>

            <div class="panel">
                <div class="panel-head">
                    <span>NOD</span>
                    <div>
                        <h2>Node projects</h2>
                        <p><?= count($nodeProjects) ?> routed app hosts</p>
                    </div>
                </div>
                <?php renderProjectCards($nodeProjects, 'No Node projects found in the mounted source directory.'); ?>
            </div>
        </section>

        <section class="grid two">
            <div class="panel">
                <div class="panel-head">
                    <span>DOC</span>
                    <div>
                        <h2>Documentation</h2>
                        <p><?= countAvailableDocs($docsRoot, $docs) ?> local docs</p>
                    </div>
                </div>
                <?php foreach ($docs as $group => $items): ?>
                    <h3><?= e($group) ?></h3>
                    <div class="cards">
                        <?php foreach ($items as [$path, $description]): ?>
                            <?php $exists = is_file(safeDocPath($docsRoot, $path)); ?>
                            <a class="card <?= $exists ? '' : 'disabled' ?>" href="<?= $exists ? '?doc=' . rawurlencode($path) : '#' ?>">
                                <strong><?= e(basename($path)) ?></strong>
                                <span><?= e($description) ?></span>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            </div>

            <div class="panel">
                <div class="panel-head">
                    <span>OPS</span>
                    <div>
                        <h2>Admin and data</h2>
                        <p><?= count($toolLinks) ?> local tools</p>
                    </div>
                </div>
                <div class="cards">
                    <?php foreach ($toolLinks as [$name, $href, $description]): ?>
                        <a class="card compact" href="<?= e($href) ?>">
                            <strong><?= e($name) ?></strong>
                            <span><?= e($description) ?></span>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>
        </section>
    </main>
    <?php
    pageEnd();
}

function renderProjectCards(array $projects, string $emptyMessage): void
{
    if (!$projects) {
        ?>
        <div class="empty">
            <strong>No projects</strong>
            <p><?= e($emptyMessage) ?></p>
        </div>
        <?php
        return;
    }
    ?>
    <div class="cards project-cards">
        <?php foreach ($projects as $project): ?>
            <a class="card project-card" href="<?= e($project['href']) ?>">
                <div class="card-title">
                    <strong><?= e($project['name']) ?></strong>
                    <em><?= e($project['type']) ?></em>
                </div>
                <span class="host"><?= e($project['host']) ?></span>
                <span><?= e($project['summary']) ?></span>
            </a>
        <?php endforeach; ?>
    </div>
    <?php
}

function renderDocument(string $docsRoot, string $path): void
{
    $fullPath = safeDocPath($docsRoot, $path);
    if (!is_file($fullPath)) {
        http_response_code(404);
        renderIndex($docsRoot, [], []);
        return;
    }

    pageStart(basename($path));
    ?>
    <main class="shell">
        <a class="back" href="/">Back to documentation</a>
        <article class="doc">
            <h1><?= e($path) ?></h1>
            <pre><?= e(file_get_contents($fullPath) ?: '') ?></pre>
        </article>
    </main>
    <?php
    pageEnd();
}

function discoverProjects(array $roots, array $nodeHosts): array
{
    $projects = [];
    $seen = [];
    foreach ($roots as $label => $root) {
        if (!is_dir($root)) {
            continue;
        }
        $entries = scandir($root) ?: [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if (in_array(strtolower($entry), ['public', 'node_modules', 'vendor'], true)) {
                continue;
            }
            $path = $root . '/' . $entry;
            if (!is_dir($path)) {
                continue;
            }
            $slug = slugify($entry);
            if ($slug === '' || isset($seen[$slug])) {
                continue;
            }
            $hasPackage = is_file($path . '/package.json');
            $isPhp = isPhpProject($path);
            if (!$isPhp && !$hasPackage) {
                continue;
            }
            $type = $isPhp ? 'PHP' : 'Node';
            $host = projectHost($slug, $type, $nodeHosts);
            $projects[] = [
                'name' => humanName($entry),
                'type' => $type,
                'host' => $host,
                'href' => 'https://' . $host . '/',
                'summary' => $type === 'PHP'
                    ? 'Apache/PHP local host'
                    : 'Node routed service',
            ];
            $seen[$slug] = true;
        }
    }
    usort($projects, static fn (array $a, array $b): int => [$a['type'], $a['name']] <=> [$b['type'], $b['name']]);
    return $projects;
}

function projectsByType(array $projects, string $type): array
{
    return array_values(array_filter($projects, static fn (array $project): bool => $project['type'] === $type));
}

function isPhpProject(string $path): bool
{
    if (is_file($path . '/composer.json') || is_file($path . '/public/index.php') || is_file($path . '/index.php')) {
        return true;
    }
    foreach (glob($path . '/public/*.php') ?: [] as $file) {
        if (is_file($file)) {
            return true;
        }
    }
    return false;
}

function parseNodeProjectHosts(): array
{
    $hosts = [];
    $raw = getenv('NODE_PROJECT_HOSTS') ?: '';
    foreach (explode(',', $raw) as $entry) {
        $entry = trim($entry);
        if ($entry === '') {
            continue;
        }
        $parts = preg_split('/[:=]/', $entry, 2);
        if (!$parts || count($parts) !== 2) {
            continue;
        }
        $slug = slugify($parts[0]);
        $host = strtolower(trim($parts[1]));
        if ($slug !== '' && preg_match('/^[a-z0-9.-]+$/', $host)) {
            $hosts[$slug] = $host;
        }
    }
    return $hosts;
}

function projectHost(string $slug, string $type, array $nodeHosts): string
{
    if ($type === 'Node' && isset($nodeHosts[$slug])) {
        return $nodeHosts[$slug];
    }
    return $slug . '.localhost.com';
}

function slugify(string $value): string
{
    return trim(strtolower((string) preg_replace('/[^a-z0-9-]+/i', '-', $value)), '-');
}

function safeDocPath(string $root, string $path): string
{
    $normalized = str_replace('\\', '/', $path);
    if (str_contains($normalized, '..')) {
        return $root . '/__invalid__';
    }
    return $root . '/' . $normalized;
}

function countAvailableDocs(string $docsRoot, array $docs): int
{
    $count = 0;
    foreach ($docs as $items) {
        foreach ($items as [$path]) {
            if (is_file(safeDocPath($docsRoot, $path))) {
                $count++;
            }
        }
    }
    return $count;
}

function humanName(string $value): string
{
    return ucwords(str_replace(['-', '_'], ' ', $value));
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pageStart(string $title): void
{
    ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title) ?></title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #0b1117;
            --panel: #121a23;
            --panel-2: #172231;
            --text: #eef5ff;
            --muted: #9eb0c5;
            --line: #263547;
            --accent: #76e4c5;
            --accent-2: #8fb7ff;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); color: var(--text); }
        a { color: inherit; text-decoration: none; }
        .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 48px; }
        .hero { display: flex; align-items: end; justify-content: space-between; gap: 24px; padding: 26px 0 24px; border-bottom: 1px solid var(--line); }
        .eyebrow { margin: 0 0 8px; color: var(--accent); font-size: 13px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
        h1 { margin: 0; font-size: clamp(34px, 5vw, 64px); line-height: .96; letter-spacing: 0; }
        h2 { margin: 0; font-size: 22px; }
        .panel-head p { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
        h3 { margin: 22px 0 10px; color: var(--muted); font-size: 13px; text-transform: uppercase; }
        .lede { max-width: 720px; margin: 16px 0 0; color: var(--muted); font-size: 17px; line-height: 1.6; }
        .status-grid { display: grid; grid-template-columns: repeat(3, 90px); gap: 10px; }
        .status-grid div { min-height: 76px; padding: 14px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .status-grid span { display: block; font-size: 28px; font-weight: 850; color: var(--accent-2); }
        .status-grid small { color: var(--muted); }
        .grid { display: grid; gap: 16px; margin-top: 22px; }
        .grid.two { grid-template-columns: minmax(0, 1.15fr) minmax(320px, .85fr); }
        .panel { padding: 18px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .panel-head { display: flex; gap: 12px; align-items: center; }
        .panel-head.secondary { margin-top: 28px; }
        .panel-head span { display: inline-grid; place-items: center; width: 42px; height: 42px; border: 1px solid var(--accent); border-radius: 8px; color: var(--accent); font-size: 12px; font-weight: 900; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; }
        .card { min-height: 96px; padding: 14px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; transition: transform .18s ease, border-color .18s ease, background .18s ease; }
        .card:hover { transform: translateY(-2px); border-color: var(--accent); background: #1a2838; }
        .card strong { display: block; font-size: 15px; }
        .card span { display: block; margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.45; }
        .project-grid { margin-top: 22px; }
        .project-cards { margin-top: 16px; }
        .project-card { min-height: 124px; }
        .card-title { display: flex; align-items: start; justify-content: space-between; gap: 10px; }
        .card-title em { padding: 4px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--accent); font-size: 11px; font-style: normal; font-weight: 850; }
        .card .host { color: var(--accent-2); font-weight: 800; overflow-wrap: anywhere; }
        .card.compact { min-height: 76px; }
        .card.disabled { opacity: .42; pointer-events: none; }
        .empty { padding: 18px; background: #101820; border: 1px dashed var(--line); border-radius: 8px; color: var(--muted); }
        .empty strong { color: var(--text); }
        .back { display: inline-flex; margin-bottom: 18px; color: var(--accent); font-weight: 800; }
        .doc { padding: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .doc h1 { font-size: 28px; margin-bottom: 20px; }
        pre { overflow: auto; white-space: pre-wrap; margin: 0; color: #dce8f7; line-height: 1.55; font-size: 14px; }
        @media (max-width: 860px) {
            .hero, .grid.two { display: block; }
            .status-grid { grid-template-columns: repeat(3, 1fr); margin-top: 22px; }
            .panel { margin-top: 16px; }
        }
    </style>
</head>
<body>
    <?php
}

function pageEnd(): void
{
    ?>
</body>
</html>
    <?php
}
