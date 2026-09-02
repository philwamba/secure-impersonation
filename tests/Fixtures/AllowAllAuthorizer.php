<?php

namespace Philwamba\SecureImpersonation\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class AllowAllAuthorizer implements ImpersonationAuthorizer
{
    public bool $resumeAllowed = true;

    public function authorizeStart(
        Authenticatable $impersonator,
        Authenticatable $target,
        Request $request,
    ): void {}

    public function canResume(
        Authenticatable $impersonator,
        Impersonation $impersonation,
        Request $request,
    ): bool {
        return $this->resumeAllowed;
    }
}
