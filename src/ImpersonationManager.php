<?php

namespace Philwamba\SecureImpersonation;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\Contracts\ImpersonationContext;
use Philwamba\SecureImpersonation\Events\ImpersonationEnded;
use Philwamba\SecureImpersonation\Events\ImpersonationStarted;
use Philwamba\SecureImpersonation\Exceptions\ImpersonationException;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class ImpersonationManager
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly Dispatcher $events,
        private readonly ImpersonationAuthorizer $authorizer,
        private readonly ImpersonationContext $context,
    ) {}

    public function start(Request $request, Authenticatable $target, string $reason): Impersonation
    {
        if ($this->current($request)) {
            throw new ImpersonationException('End the current impersonation before starting another one.');
        }

        $impersonator = $request->user();
        if (! $impersonator instanceof Authenticatable) {
            throw new ImpersonationException('An authenticated user is required to start impersonation.');
        }

        if (trim($reason) === '') {
            throw new ImpersonationException('An impersonation reason is required.');
        }

        $this->authorizer->authorizeStart($impersonator, $target, $request);

        [$impersonatorType, $impersonatorId] = $this->identity($impersonator);
        [$targetType, $targetId] = $this->identity($target);
        $guardName = (string) config('secure-impersonation.guard', 'web');
        $duration = max(5, (int) config('secure-impersonation.duration_minutes', 30));

        $impersonation = Impersonation::query()->create([
            'impersonator_type' => $impersonatorType,
            'impersonator_id' => $impersonatorId,
            'impersonated_type' => $targetType,
            'impersonated_id' => $targetId,
            'guard_name' => $guardName,
            'context' => $this->context->capture($request),
            'reason' => trim($reason),
            'started_at' => now(),
            'expires_at' => now()->addMinutes($duration),
            'started_ip' => $request->ip(),
            'user_agent' => mb_substr((string) $request->userAgent(), 0, 500),
        ]);

        $request->session()->put($this->sessionKey(), $impersonation->getKey());
        $request->session()->forget('auth.password_confirmed_at');
        $this->statefulGuard($guardName)->login($target);
        $this->auth->shouldUse($guardName);
        $request->setUserResolver(fn (): Authenticatable => $target);
        $request->session()->regenerate();

        $this->events->dispatch(new ImpersonationStarted($impersonation, $impersonator, $target));

        return $impersonation;
    }

    public function current(Request $request): ?Impersonation
    {
        if (! $request->hasSession()) {
            return null;
        }

        $id = $request->session()->get($this->sessionKey());

        return is_string($id) && $id !== ''
            ? Impersonation::query()->find($id)
            : null;
    }

    public function stop(Request $request, string $reason = 'manual', bool $restore = true): ?Impersonation
    {
        $impersonation = $this->current($request);
        if (! $impersonation) {
            $request->session()->forget($this->sessionKey());

            return null;
        }

        $target = $this->resolveIdentity(
            $impersonation->impersonated_type,
            $impersonation->impersonated_id,
        );
        $impersonator = $this->resolveIdentity(
            $impersonation->impersonator_type,
            $impersonation->impersonator_id,
        );

        $impersonation->forceFill([
            'ended_at' => $impersonation->ended_at ?? now(),
            'ended_reason' => $impersonation->ended_reason ?? $reason,
            'ended_ip' => $request->ip(),
        ])->save();

        $request->session()->forget($this->sessionKey());
        $request->session()->forget('auth.password_confirmed_at');

        $canRestore = $restore
            && $impersonator instanceof Authenticatable
            && $this->authorizer->canResume($impersonator, $impersonation, $request);

        if ($canRestore) {
            $this->statefulGuard($impersonation->guard_name)->login($impersonator);
            $this->auth->shouldUse($impersonation->guard_name);
            $request->setUserResolver(fn (): Authenticatable => $impersonator);
            $request->session()->regenerate();
        } elseif ($restore) {
            $this->statefulGuard($impersonation->guard_name)->logout();
            $request->setUserResolver(fn () => null);
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        $this->events->dispatch(new ImpersonationEnded(
            $impersonation,
            $impersonator,
            $target,
            $canRestore,
        ));

        return $impersonation;
    }

    public function resolveImpersonator(Impersonation $impersonation): ?Authenticatable
    {
        return $this->resolveIdentity($impersonation->impersonator_type, $impersonation->impersonator_id);
    }

    public function contextMatches(Request $request, Impersonation $impersonation): bool
    {
        return $this->context->matches($request, $impersonation);
    }

    public function operatorCanResume(Request $request, Impersonation $impersonation): bool
    {
        $impersonator = $this->resolveImpersonator($impersonation);

        return $impersonator instanceof Authenticatable
            && $this->authorizer->canResume($impersonator, $impersonation, $request);
    }

    public function clear(Request $request): void
    {
        if ($request->hasSession()) {
            $request->session()->forget($this->sessionKey());
        }
    }

    private function sessionKey(): string
    {
        return (string) config('secure-impersonation.session_key', 'secure_impersonation_id');
    }

    /** @return array{string, string} */
    private function identity(Authenticatable $user): array
    {
        if (! $user instanceof Model) {
            throw new ImpersonationException('Impersonated users must be Eloquent models.');
        }

        return [$user->getMorphClass(), (string) $user->getAuthIdentifier()];
    }

    private function resolveIdentity(string $type, string $id): ?Authenticatable
    {
        $class = Relation::getMorphedModel($type) ?? $type;
        if (! class_exists($class)) {
            return null;
        }

        $model = new $class;
        if (! $model instanceof Model || ! $model instanceof Authenticatable) {
            return null;
        }

        $resolved = $model->newQuery()->find($id);

        return $resolved instanceof Authenticatable ? $resolved : null;
    }

    private function statefulGuard(string $guardName): StatefulGuard
    {
        $guard = $this->auth->guard($guardName);
        if (! $guard instanceof StatefulGuard) {
            throw new ImpersonationException("The [{$guardName}] guard must be stateful.");
        }

        return $guard;
    }
}
