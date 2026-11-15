<?php
/**
 * Plugin Name: Lab Hardening
 * Description: Applica solo le correzioni elencate in LAB_FIXES (variabile d'ambiente).
 *              Serve a creare siti con configurazioni di sicurezza note per il benchmark.
 */

$lab_fixes = array_filter(array_map('trim', explode(',', getenv('LAB_FIXES') ?: '')));
$lab_on = function ($k) use ($lab_fixes) {
    return in_array($k, $lab_fixes, true);
};

// 1) Utenti non elencabili via REST API per chi non ha fatto login
if ($lab_on('utenti')) {
    add_filter('rest_endpoints', function ($endpoints) {
        if (!is_user_logged_in()) {
            unset($endpoints['/wp/v2/users']);
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    });
}

// 2) Nessun redirect /?author=N -> /author/username/
if ($lab_on('author')) {
    add_action('template_redirect', function () {
        if (!is_admin() && isset($_GET['author'])) {
            wp_redirect(home_url('/'), 301);
            exit;
        }
    }, 1);
}

// 3) XML-RPC bloccato del tutto.
// NOTA: add_filter('xmlrpc_enabled', '__return_false') NON basta: blocca solo i
// metodi che richiedono il login, mentre system.listMethods resta raggiungibile.
if ($lab_on('xmlrpc')) {
    add_action('init', function () {
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            status_header(403);
            exit;
        }
    }, 0);
}

// 4) Header di sicurezza sul sito pubblico
if ($lab_on('header')) {
    add_action('send_headers', function () {
        if (is_admin()) {
            return;
        }
        header('Strict-Transport-Security: max-age=300');
        header("Content-Security-Policy: default-src 'self' 'unsafe-inline' data:; frame-ancestors 'self'");
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    });
}

// 5) Nessuna versione di WordPress nel meta generator
if ($lab_on('versione')) {
    remove_action('wp_head', 'wp_generator');
}
