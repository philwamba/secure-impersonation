<?php

namespace Philwamba\SecureImpersonation\Contracts;

use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Models\Impersonation;

interface ImpersonationContext
{
    /** @return array<string, mixed> */
    public function capture(Request $request): array;

    public function matches(Request $request, Impersonation $impersonation): bool;
}
