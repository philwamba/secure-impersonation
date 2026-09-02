<?php

namespace Philwamba\SecureImpersonation\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Events\ImpersonatedRequestBlocked;
use Philwamba\SecureImpersonation\Events\ImpersonatedRequestViewed;
use Philwamba\SecureImpersonation\ImpersonationManager;
use Philwamba\SecureImpersonation\Models\Impersonation;
use Symfony\Component\HttpFoundation\Response;

final class GuardImpersonation
{
    public function __construct(
        private readonly ImpersonationManager $manager,
        private readonly Dispatcher $events,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $impersonation = $this->manager->current($request);
        if (! $impersonation) {
            $this->manager->clear($request);

            return $next($request);
        }

        if ($impersonation->ended_at || $impersonation->expires_at->isPast()) {
            $reason = $impersonation->ended_at ? 'invalidated' : 'expired';
            $this->manager->stop($request, $reason);

            return new JsonResponse([
                'message' => 'Impersonation ended and the original session was restored. Retry the request only if you intend to act as yourself.',
                'reason' => $reason,
            ], 409);
        }

        if (! $this->manager->operatorCanResume($request, $impersonation)) {
            $this->manager->stop($request, 'operator_unavailable');

            return new JsonResponse([
                'message' => 'The original account is no longer authorized. Impersonation has ended.',
            ], 401);
        }

        $current = $request->user();
        if (! $current instanceof Authenticatable
            || ! $current instanceof Model
            || $current->getMorphClass() !== $impersonation->impersonated_type
            || (string) $current->getAuthIdentifier() !== (string) $impersonation->impersonated_id) {
            $this->manager->stop($request, 'invalidated');

            return new JsonResponse([
                'message' => 'The impersonation session was invalid and has ended.',
            ], 409);
        }

        if (! $this->manager->contextMatches($request, $impersonation)) {
            return $this->blocked($request, $impersonation, 'The impersonation context cannot be changed.');
        }

        $safeMethods = array_map('strtoupper', (array) config(
            'secure-impersonation.safe_methods',
            ['GET', 'HEAD', 'OPTIONS'],
        ));
        if ((bool) config('secure-impersonation.block_unsafe_methods', true)
            && ! in_array(strtoupper($request->method()), $safeMethods, true)) {
            return $this->blocked(
                $request,
                $impersonation,
                'Impersonation is read-only. End impersonation before changing or submitting data.',
            );
        }

        $response = $next($request);

        if ((bool) config('secure-impersonation.audit_views', false)) {
            $this->events->dispatch(new ImpersonatedRequestViewed(
                $impersonation,
                $request->method(),
                '/'.$request->path(),
                $response->getStatusCode(),
            ));
        }

        return $response;
    }

    private function blocked(Request $request, Impersonation $impersonation, string $reason): JsonResponse
    {
        $this->events->dispatch(new ImpersonatedRequestBlocked(
            $impersonation,
            $request->method(),
            '/'.$request->path(),
            $reason,
        ));

        return new JsonResponse(['message' => $reason], 403);
    }
}
