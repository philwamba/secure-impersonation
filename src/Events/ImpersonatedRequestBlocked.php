<?php

namespace Philwamba\SecureImpersonation\Events;

use Philwamba\SecureImpersonation\Models\Impersonation;

final class ImpersonatedRequestBlocked
{
    public function __construct(
        public readonly Impersonation $impersonation,
        public readonly string $method,
        public readonly string $path,
        public readonly string $reason,
    ) {}
}
