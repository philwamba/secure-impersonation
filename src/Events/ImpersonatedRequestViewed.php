<?php

namespace Philwamba\SecureImpersonation\Events;

use Philwamba\SecureImpersonation\Models\Impersonation;

final class ImpersonatedRequestViewed
{
    public function __construct(
        public readonly Impersonation $impersonation,
        public readonly string $method,
        public readonly string $path,
        public readonly int $status,
    ) {}
}
