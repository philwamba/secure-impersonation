<?php

namespace Philwamba\SecureImpersonation\Middleware;

use Closure;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Events\ImpersonatedRequestBlocked;
use Philwamba\SecureImpersonation\ImpersonationManager;
use Symfony\Component\HttpFoundation\Response;

final class ProtectFromImpersonation
{
    public function __construct(
        private readonly ImpersonationManager $manager,
        private readonly Dispatcher $events,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $impersonation = $this->manager->current($request);
        if (! $impersonation) {
            return $next($request);
        }

        $reason = 'This resource is unavailable during impersonation.';
        $this->events->dispatch(new ImpersonatedRequestBlocked(
            $impersonation,
            $request->method(),
            '/'.$request->path(),
            $reason,
        ));

        return new JsonResponse(['message' => $reason], 403);
    }
}
