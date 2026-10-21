<?php
// Simulates an LFI vulnerability for CVE-2026-109619 session injection PoC.
// In real applications this would be an include/require with user-controlled path.
$page = $_GET['page'] ?? '';

if (preg_match('#^/var/lib/php/sessions/sess_#', $page)) {
    include $page;
} else {
    echo "page parameter required\n";
}
