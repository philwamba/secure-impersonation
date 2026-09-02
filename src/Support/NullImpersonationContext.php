<?php

namespace Philwamba\SecureImpersonation\Support;

use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Contracts\ImpersonationContext;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class NullImpersonationContext implements ImpersonationContext
{
    public function capture(Request $request): array
    {
        return [];
    }

    public function matches(Request $request, Impersonation $impersonation): bool
    {
        return true;
    }
}
