<?php

namespace Philwamba\SecureImpersonation\Support;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class DenyAllAuthorizer implements ImpersonationAuthorizer
{
    public function authorizeStart(
        Authenticatable $impersonator,
        Authenticatable $target,
        Request $request,
    ): void {
        throw new AuthorizationException(
            'Impersonation is disabled until the application binds an ImpersonationAuthorizer.',
        );
    }

    public function canResume(
        Authenticatable $impersonator,
        Impersonation $impersonation,
        Request $request,
    ): bool {
        return false;
    }
}
