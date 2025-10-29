<?php
declare(strict_types=1);

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$dsnHost = getenv('DATABASE') ?: '127.0.0.1';
$dbName  = getenv('NAME') ?: 'sunsets';
$dbUser  = getenv('USER') ?: 'user';
$dbPass  = getenv('USERPASS') ?: '';

try {
    $pdo = new PDO("mysql:host=$dsnHost;dbname=$dbName;charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => 'DB_CONNECTION_FAILED']);
    exit;
}

function ensureTables(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS blogs (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NULL,
        image VARCHAR(512) NULL,
        redirect VARCHAR(512) NULL,
        buttonText VARCHAR(64) DEFAULT 'Read',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    $pdo->exec("CREATE TABLE IF NOT EXISTS issues (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NULL,
        image VARCHAR(512) NULL,
        redirect VARCHAR(512) NULL,
        buttonText VARCHAR(64) DEFAULT 'View',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    $pdo->exec("CREATE TABLE IF NOT EXISTS newsletter_subscriptions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    $pdo->exec("CREATE TABLE IF NOT EXISTS sponsor_applications (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        companyName VARCHAR(255) NOT NULL,
        contactName VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(64) NULL,
        businessType VARCHAR(64) NOT NULL,
        package VARCHAR(64) NOT NULL,
        message TEXT NULL,
        applicationDate DATETIME NOT NULL,
        status VARCHAR(32) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
}

ensureTables($pdo);

$uri = $_SERVER['REQUEST_URI'] ?? '/api';
$path = parse_url($uri, PHP_URL_PATH);

function jsonInput(): array {
function requireAdmin(): void {
    $adminUser = getenv('ADMIN_USER') ?: 'admin';
    $adminPass = getenv('ADMIN_PASS') ?: 'admin';
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (stripos($hdr, 'Basic ') !== 0) { http_response_code(401); header('WWW-Authenticate: Basic'); echo json_encode(['error'=>'AUTH_REQUIRED']); exit; }
    $decoded = base64_decode(substr($hdr, 6));
    if (!$decoded || strpos($decoded, ':') === false) { http_response_code(401); echo json_encode(['error'=>'AUTH_MALFORMED']); exit; }
    list($u,$p) = explode(':', $decoded, 2);
    if (!hash_equals($adminUser, $u) || !hash_equals($adminPass, $p)) { http_response_code(403); echo json_encode(['error'=>'FORBIDDEN']); exit; }
}

    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

if ($path === '/api/blogs' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $pdo->query("SELECT id, title, description, image, redirect, buttonText, created_at FROM blogs ORDER BY created_at DESC LIMIT 100");
    echo json_encode($stmt->fetchAll());
    exit;
}

if ($path === '/api/issues' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $pdo->query("SELECT id, title, description, image, redirect, buttonText, created_at FROM issues ORDER BY created_at DESC LIMIT 100");
    echo json_encode($stmt->fetchAll());
    exit;
}

// Admin: create blog
if ($path === '/api/blogs' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireAdmin();
    $data = jsonInput();
    $stmt = $pdo->prepare('INSERT INTO blogs (title, description, image, redirect, buttonText) VALUES (:title,:description,:image,:redirect,:buttonText)');
    $stmt->execute([
        ':title' => trim($data['title'] ?? ''),
        ':description' => trim($data['description'] ?? ''),
        ':image' => trim($data['image'] ?? ''),
        ':redirect' => trim($data['redirect'] ?? ''),
        ':buttonText' => trim($data['buttonText'] ?? 'Read'),
    ]);
    echo json_encode(['ok'=>true, 'id' => $pdo->lastInsertId()]);
    exit;
}

// Admin: create issue
if ($path === '/api/issues' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireAdmin();
    $data = jsonInput();
    $stmt = $pdo->prepare('INSERT INTO issues (title, description, image, redirect, buttonText) VALUES (:title,:description,:image,:redirect,:buttonText)');
    $stmt->execute([
        ':title' => trim($data['title'] ?? ''),
        ':description' => trim($data['description'] ?? ''),
        ':image' => trim($data['image'] ?? ''),
        ':redirect' => trim($data['redirect'] ?? ''),
        ':buttonText' => trim($data['buttonText'] ?? 'View'),
    ]);
    echo json_encode(['ok'=>true, 'id' => $pdo->lastInsertId()]);
    exit;
}

// Admin: delete blog
if ($path === '/api/blogs' && $_SERVER['REQUEST_METHOD'] === 'DELETE') {
    requireAdmin();
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) { http_response_code(422); echo json_encode(['error'=>'INVALID_ID']); exit; }
    $stmt = $pdo->prepare('DELETE FROM blogs WHERE id = :id');
    $stmt->execute([':id'=>$id]);
    echo json_encode(['ok'=>true]);
    exit;
}

// Admin: delete issue
if ($path === '/api/issues' && $_SERVER['REQUEST_METHOD'] === 'DELETE') {
    requireAdmin();
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) { http_response_code(422); echo json_encode(['error'=>'INVALID_ID']); exit; }
    $stmt = $pdo->prepare('DELETE FROM issues WHERE id = :id');
    $stmt->execute([':id'=>$id]);
    echo json_encode(['ok'=>true]);
    exit;
}

if ($path === '/api/newsletter/subscribe' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = jsonInput();
    $email = trim($data['email'] ?? '');
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(422);
        echo json_encode(['error' => 'INVALID_EMAIL']);
        exit;
    }
    try {
        $stmt = $pdo->prepare('INSERT INTO newsletter_subscriptions (email) VALUES (:email)');
        $stmt->execute([':email' => $email]);
        echo json_encode(['ok' => true]);
    } catch (PDOException $e) {
        if ((int)$e->getCode() === 23000) { // duplicate
            echo json_encode(['ok' => true, 'message' => 'ALREADY_SUBSCRIBED']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'SUBSCRIBE_FAILED']);
        }
    }
    exit;
}

if ($path === '/api/sponsor/apply' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = jsonInput();
    $required = ['companyName','contactName','email','businessType','package'];
    foreach ($required as $k) { if (empty($data[$k])) { http_response_code(422); echo json_encode(['error'=>'MISSING_'.$k]); exit; } }
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) { http_response_code(422); echo json_encode(['error'=>'INVALID_EMAIL']); exit; }
    $stmt = $pdo->prepare('INSERT INTO sponsor_applications (companyName, contactName, email, phone, businessType, package, message, applicationDate, status) VALUES (:companyName,:contactName,:email,:phone,:businessType,:package,:message,:applicationDate,:status)');
    $stmt->execute([
        ':companyName' => trim($data['companyName']),
        ':contactName' => trim($data['contactName']),
        ':email' => trim($data['email']),
        ':phone' => trim($data['phone'] ?? ''),
        ':businessType' => trim($data['businessType']),
        ':package' => trim($data['package']),
        ':message' => trim($data['message'] ?? ''),
        ':applicationDate' => date('Y-m-d H:i:s'),
        ':status' => 'pending',
    ]);
    echo json_encode(['ok' => true]);
    exit;
}

http_response_code(404);
echo json_encode(['error' => 'NOT_FOUND']);
<?php


