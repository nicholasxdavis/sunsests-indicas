<?php
/**
 * Sunsets & Indicas - Cannabis Magazine
 * Main entry point for the website
 * 
 * This file serves as the main entry point and redirects to the main/index.html
 * while providing PHP functionality for future enhancements.
 */

// Set proper headers
header('Content-Type: text/html; charset=UTF-8');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

// Check if we're in development mode
$isDevelopment = (isset($_SERVER['HTTP_HOST']) && strpos($_SERVER['HTTP_HOST'], 'localhost') !== false);

// Define base URL
$baseUrl = $isDevelopment ? 'http://localhost' : 'https://sunsetsandindicas.com';

// Handle different routes
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);

// Route handling
switch ($path) {
    case '/':
    case '/index.php':
        // Load the main index page
        include 'main/index.html';
        break;
        
    case '/admin':
    case '/admin/':
        // Redirect to admin dashboard
        header('Location: /admin/index.html');
        exit;
        break;
        
    case '/api':
    case '/api/':
    default:
        if (strpos($path, '/api') === 0) {
            include __DIR__ . '/api/index.php';
            break;
        }
        
    default:
        // Check if it's a static file request
        if (file_exists('main' . $path)) {
            // Serve static files from main directory
            $filePath = 'main' . $path;
            $mimeType = mime_content_type($filePath);
            header('Content-Type: ' . $mimeType);
            readfile($filePath);
        } else {
            // 404 - redirect to 404 page
            header('HTTP/1.0 404 Not Found');
            include '404.html';
        }
        break;
}

// Log access for analytics (in production)
if (!$isDevelopment) {
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'request_uri' => $requestUri,
        'referer' => $_SERVER['HTTP_REFERER'] ?? 'direct'
    ];
    
    // Simple file logging (in production, use proper logging service)
    error_log(json_encode($logData) . "\n", 3, 'logs/access.log');
}
?>


