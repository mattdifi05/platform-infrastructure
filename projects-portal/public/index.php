<?php
declare(strict_types=1);

$docsRoot = '/var/www/infra-docs';
$stateFile = getenv('PROJECT_STATE_FILE') ?: '/var/www/project-state/projects.json';
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

$projectState = readProjectState($stateFile);
$projects = discoverProjects($projectRoots, parseNodeProjectHosts(), $projectState);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    handleProjectAction($stateFile, $projects);
    exit;
}

$selectedDoc = $_GET['doc'] ?? '';
if (is_string($selectedDoc) && isset($docMap[$selectedDoc])) {
    renderDocument($docsRoot, $selectedDoc);
    exit;
}

renderIndex($docsRoot, $docs, $projects);

function handleProjectAction(string $stateFile, array $projects): void
{
    $action = (string) ($_POST['action'] ?? '');
    if ($action !== 'toggle') {
        http_response_code(400);
        renderMessage('Invalid action', 'The requested dashboard action is not supported.');
        return;
    }

    $slug = slugify((string) ($_POST['slug'] ?? ''));
    $knownSlugs = array_fill_keys(array_column($projects, 'slug'), true);
    if ($slug === '' || !isset($knownSlugs[$slug])) {
        http_response_code(404);
        renderMessage('Project not found', 'The selected project is not mounted in the local source directory.');
        return;
    }

    saveProjectState($stateFile, $slug, (string) ($_POST['enabled'] ?? '') === '1');
    header('Location: /#project-' . rawurlencode($slug), true, 303);
}

function renderIndex(string $docsRoot, array $docs, array $projects): void
{
    $phpProjects = projectsByType($projects, 'PHP');
    $nodeProjects = projectsByType($projects, 'Node');
    $activeProjects = count(array_filter($projects, static fn (array $project): bool => $project['enabled']));
    $toolLinks = [
        ['phpMyAdmin', 'https://phpmyadmin.localhost.com/', 'Database administration'],
        ['Keycloak', 'https://auth.localhost.com/', 'Identity provider'],
        ['Grafana', 'https://grafana.localhost.com/', 'Dashboards and metrics'],
        ['MinIO', 'https://minio.localhost.com/', 'Object storage console'],
    ];

    pageStart('Projects Dashboard');
    ?>
    <main class="shell">
        <section class="hero">
            <div>
                <p class="eyebrow">Local infrastructure</p>
                <h1>Projects dashboard</h1>
                <p class="lede">PHP and Node projects mounted from the shared source directory, grouped by runtime and routed through local HTTPS hostnames.</p>
            </div>
            <div class="status-grid" aria-label="Local status">
                <div><span><?= e((string) count($projects)) ?></span><small>projects</small></div>
                <div><span><?= e((string) $activeProjects) ?></span><small>active</small></div>
                <div><span><?= e((string) (count($projects) - $activeProjects)) ?></span><small>off</small></div>
                <div><span><?= e((string) count($nodeProjects)) ?></span><small>node</small></div>
            </div>
        </section>

        <section class="grid two project-grid">
            <div class="panel">
                <div class="panel-head">
                    <span>PHP</span>
                    <div>
                        <h2>PHP projects</h2>
                        <p><?= e((string) count($phpProjects)) ?> Apache hosts</p>
                    </div>
                </div>
                <?php renderProjectCards($phpProjects, 'No PHP projects found in the mounted source directory.'); ?>
            </div>

            <div class="panel">
                <div class="panel-head">
                    <span>NOD</span>
                    <div>
                        <h2>Node projects</h2>
                        <p><?= e((string) count($nodeProjects)) ?> routed app hosts</p>
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
                        <p><?= e((string) countAvailableDocs($docsRoot, $docs)) ?> local docs</p>
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
                        <p><?= e((string) count($toolLinks)) ?> local tools</p>
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
            <div id="project-<?= e($project['slug']) ?>" class="card project-card <?= $project['enabled'] ? '' : 'is-off' ?>">
                <div class="card-title">
                    <strong><?= e($project['name']) ?></strong>
                    <em><?= e($project['type']) ?></em>
                </div>
                <span class="host"><?= e($project['host']) ?></span>
                <span><?= e($project['summary']) ?></span>
                <div class="project-actions">
                    <span class="state <?= $project['enabled'] ? 'on' : 'off' ?>"><?= $project['enabled'] ? 'Active' : 'Off' ?></span>
                    <?php if ($project['enabled']): ?>
                        <a class="button open" href="<?= e($project['href']) ?>">Open</a>
                    <?php else: ?>
                        <span class="button muted">Open</span>
                    <?php endif; ?>
                    <form method="post" action="/">
                        <input type="hidden" name="action" value="toggle">
                        <input type="hidden" name="slug" value="<?= e($project['slug']) ?>">
                        <input type="hidden" name="enabled" value="<?= $project['enabled'] ? '0' : '1' ?>">
                        <button class="button <?= $project['enabled'] ? 'danger' : 'enable' ?>" type="submit">
                            <?= $project['enabled'] ? 'Disable' : 'Enable' ?>
                        </button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <?php
}

function renderDocument(string $docsRoot, string $path): void
{
    $fullPath = safeDocPath($docsRoot, $path);
    if (!is_file($fullPath)) {
        http_response_code(404);
        renderMessage('Document not found', 'The requested local document is not available.');
        return;
    }

    pageStart(basename($path));
    ?>
    <main class="shell">
        <a class="back" href="/">Back to dashboard</a>
        <article class="doc">
            <h1><?= e($path) ?></h1>
            <pre><?= e(file_get_contents($fullPath) ?: '') ?></pre>
        </article>
    </main>
    <?php
    pageEnd();
}

function renderMessage(string $title, string $message): void
{
    pageStart($title);
    ?>
    <main class="shell">
        <section class="panel message">
            <h1><?= e($title) ?></h1>
            <p><?= e($message) ?></p>
            <a class="back" href="/">Back to dashboard</a>
        </section>
    </main>
    <?php
    pageEnd();
}

function discoverProjects(array $roots, array $nodeHosts, array $state): array
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
            $enabled = projectEnabled($state, $slug);
            $projects[] = [
                'slug' => $slug,
                'name' => humanName($entry),
                'type' => $type,
                'host' => $host,
                'href' => 'https://' . $host . '/',
                'enabled' => $enabled,
                'summary' => $type === 'PHP'
                    ? 'Apache/PHP local host'
                    : 'Node routed service',
            ];
            $seen[$slug] = true;
        }
    }
    usort($projects, static function (array $a, array $b): int {
        $typeOrder = ['PHP' => 0, 'Node' => 1];
        return [$typeOrder[$a['type']] ?? 9, $a['name']] <=> [$typeOrder[$b['type']] ?? 9, $b['name']];
    });
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
        $separator = str_contains($entry, '=') ? strpos($entry, '=') : strpos($entry, ':');
        if ($separator === false || $separator <= 0) {
            continue;
        }
        $slug = slugify(substr($entry, 0, $separator));
        $host = strtolower(trim(substr($entry, $separator + 1)));
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
    $suffix = getenv('PROJECT_HOST_SUFFIX') ?: '.localhost.com';
    if ($suffix !== '' && $suffix[0] !== '.') {
        $suffix = '.' . $suffix;
    }
    return $slug . $suffix;
}

function readProjectState(string $stateFile): array
{
    $raw = @file_get_contents($stateFile);
    return decodeProjectState(is_string($raw) ? $raw : '');
}

function decodeProjectState(string $raw): array
{
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        $decoded = [];
    }
    if (!isset($decoded['projects']) || !is_array($decoded['projects'])) {
        $decoded['projects'] = [];
    }
    return $decoded;
}

function projectEnabled(array $state, string $slug): bool
{
    return ($state['projects'][$slug]['enabled'] ?? true) !== false;
}

function saveProjectState(string $stateFile, string $slug, bool $enabled): void
{
    $directory = dirname($stateFile);
    if (!is_dir($directory) && !mkdir($directory, 0775, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create project state directory.');
    }

    $handle = fopen($stateFile, 'c+');
    if ($handle === false) {
        throw new RuntimeException('Unable to open project state file.');
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock project state file.');
        }
        rewind($handle);
        $raw = stream_get_contents($handle);
        $state = decodeProjectState(is_string($raw) ? $raw : '');
        $state['projects'][$slug] = [
            'enabled' => $enabled,
            'updatedAt' => gmdate(DATE_ATOM),
        ];
        $encoded = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            throw new RuntimeException('Unable to encode project state.');
        }
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, $encoded . PHP_EOL);
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
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
            --danger: #ff8b8b;
            --warn: #f6d66f;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); color: var(--text); }
        a { color: inherit; text-decoration: none; }
        button, input { font: inherit; }
        .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 48px; }
        .hero { display: flex; align-items: end; justify-content: space-between; gap: 24px; padding: 26px 0 24px; border-bottom: 1px solid var(--line); }
        .eyebrow { margin: 0 0 8px; color: var(--accent); font-size: 13px; font-weight: 800; letter-spacing: 0; text-transform: uppercase; }
        h1 { margin: 0; font-size: 54px; line-height: 1; letter-spacing: 0; }
        h2 { margin: 0; font-size: 22px; }
        .panel-head p { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
        h3 { margin: 22px 0 10px; color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0; }
        .lede { max-width: 720px; margin: 16px 0 0; color: var(--muted); font-size: 17px; line-height: 1.6; }
        .status-grid { display: grid; grid-template-columns: repeat(4, 84px); gap: 10px; }
        .status-grid div { min-height: 76px; padding: 14px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .status-grid span { display: block; font-size: 28px; font-weight: 850; color: var(--accent-2); }
        .status-grid small { color: var(--muted); }
        .grid { display: grid; gap: 16px; margin-top: 22px; }
        .grid.two { grid-template-columns: minmax(0, 1.15fr) minmax(320px, .85fr); }
        .panel { padding: 18px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .panel-head { display: flex; gap: 12px; align-items: center; }
        .panel-head span { display: inline-grid; place-items: center; width: 42px; height: 42px; border: 1px solid var(--accent); border-radius: 8px; color: var(--accent); font-size: 12px; font-weight: 900; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; }
        .card { min-height: 96px; padding: 14px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; transition: transform .18s ease, border-color .18s ease, background .18s ease; }
        a.card:hover, .project-card:hover { transform: translateY(-2px); border-color: var(--accent); background: #1a2838; }
        .card strong { display: block; font-size: 15px; }
        .card span { display: block; margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.45; }
        .project-grid { margin-top: 22px; }
        .project-cards { margin-top: 16px; }
        .project-card { min-height: 160px; display: flex; flex-direction: column; gap: 4px; }
        .project-card.is-off { opacity: .76; }
        .project-card.is-off .host { color: var(--muted); }
        .card-title { display: flex; align-items: start; justify-content: space-between; gap: 10px; }
        .card-title em { padding: 4px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--accent); font-size: 11px; font-style: normal; font-weight: 850; }
        .card .host { color: var(--accent-2); font-weight: 800; overflow-wrap: anywhere; }
        .project-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: auto; padding-top: 12px; }
        .state { min-width: 62px; padding: 6px 9px; border-radius: 999px; border: 1px solid var(--line); font-size: 12px; font-weight: 850; text-align: center; }
        .state.on { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 50%, var(--line)); }
        .state.off { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 45%, var(--line)); }
        .button { display: inline-flex; align-items: center; justify-content: center; min-height: 34px; padding: 0 12px; border: 1px solid var(--line); border-radius: 8px; background: #101820; color: var(--text); font-size: 13px; font-weight: 850; cursor: pointer; }
        .button.open, .button.enable { border-color: color-mix(in srgb, var(--accent) 60%, var(--line)); color: var(--accent); }
        .button.danger { border-color: color-mix(in srgb, var(--danger) 60%, var(--line)); color: var(--danger); }
        .button.muted { color: var(--muted); cursor: not-allowed; opacity: .55; }
        .button:hover { background: #1d2c3e; }
        .card.compact { min-height: 76px; }
        .card.disabled { opacity: .42; pointer-events: none; }
        .empty { padding: 18px; background: #101820; border: 1px dashed var(--line); border-radius: 8px; color: var(--muted); }
        .empty strong { color: var(--text); }
        .back { display: inline-flex; margin-bottom: 18px; color: var(--accent); font-weight: 800; }
        .doc { padding: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        .doc h1 { font-size: 28px; margin-bottom: 20px; }
        .message h1 { font-size: 32px; }
        pre { overflow: auto; white-space: pre-wrap; margin: 0; color: #dce8f7; line-height: 1.55; font-size: 14px; }
        @media (max-width: 860px) {
            .hero, .grid.two { display: block; }
            h1 { font-size: 38px; }
            .status-grid { grid-template-columns: repeat(2, 1fr); margin-top: 22px; }
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
