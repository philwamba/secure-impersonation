<?php

namespace Philwamba\SecureImpersonation\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Models\Impersonation;

interface ImpersonationAuthorizer
{
    public function authorizeStart(
        Authenticatable $impersonator,
        Authenticatable $target,
        Request $request,
    ): void;

    public function canResume(
        Authenticatable $impersonator,
        Impersonation $impersonation,
        Request $request,
    ): bool;
}
