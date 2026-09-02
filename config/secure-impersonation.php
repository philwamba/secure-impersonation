<?php

return [
    'guard' => env('SECURE_IMPERSONATION_GUARD', 'web'),
    'duration_minutes' => (int) env('SECURE_IMPERSONATION_DURATION_MINUTES', 30),
    'session_key' => 'secure_impersonation_id',
    'table' => 'secure_impersonations',
    'block_unsafe_methods' => true,
    'safe_methods' => ['GET', 'HEAD', 'OPTIONS'],
    'audit_views' => false,
];
