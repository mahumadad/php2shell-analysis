<?php
require_once __DIR__ . '/autoload.php';
session_start();

echo "PHP " . PHP_VERSION . "\n";
echo "Serializer: " . ini_get('session.serialize_handler') . "\n";
echo "Session ID: " . session_id() . "\n";
echo "upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "\n\n";
echo "Session data:\n";
print_r($_SESSION);
