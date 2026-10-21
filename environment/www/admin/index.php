<?php
require_once __DIR__ . '/../autoload.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['data'])) {
    $_SESSION['data'] = $_POST['data'];
    echo "OK\n";
}

echo "Serializer: " . ini_get('session.serialize_handler') . "\n";
echo "Session ID: " . session_id() . "\n";
