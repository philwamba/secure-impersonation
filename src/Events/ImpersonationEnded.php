<?php

namespace Philwamba\SecureImpersonation\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class ImpersonationEnded
{
    public function __construct(
        public readonly Impersonation $impersonation,
        public readonly ?Authenticatable $impersonator,
        public readonly ?Authenticatable $impersonated,
        public readonly bool $restored,
    ) {}
}
