# Secure Impersonation for Laravel

`philwamba/secure-impersonation` provides server-side, session-based user impersonation with secure session rotation, an absolute expiry, persistent records, read-only middleware, protected-route middleware, application-defined authorization and lifecycle events.

The package denies all impersonation by default. An application must bind its own `ImpersonationAuthorizer` before anyone can start or resume a session.

## Requirements

- PHP 8.3 or newer
- Laravel 12 or 13
- A stateful Laravel authentication guard

## Installation

```bash
composer require philwamba/secure-impersonation
php artisan vendor:publish --tag=secure-impersonation-config
php artisan vendor:publish --tag=secure-impersonation-migrations
php artisan migrate
```

The package service provider is registered through Laravel package discovery.

## Authorization

Create an application-specific implementation of `ImpersonationAuthorizer`:

```php
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\Models\Impersonation;

final class AppImpersonationAuthorizer implements ImpersonationAuthorizer
{
    public function authorizeStart(
        Authenticatable $impersonator,
        Authenticatable $target,
        Request $request,
    ): void {
        throw_unless($impersonator->can('impersonate', $target), AuthorizationException::class);
    }

    public function canResume(
        Authenticatable $impersonator,
        Impersonation $impersonation,
        Request $request,
    ): bool {
        return $impersonator->can('resumeImpersonation', $impersonation);
    }
}
```

Bind it in an application service provider:

```php
$this->app->bind(
    \Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer::class,
    \App\Security\AppImpersonationAuthorizer::class,
);
```

The authorizer should explicitly reject self-impersonation, privileged targets, disabled accounts, unverified accounts and targets outside the operator's tenant or institution.

## Starting and stopping

Applications own their controllers and response format. Require recent password confirmation and validate a meaningful reason before calling the manager:

```php
Route::post('/admin/users/{user}/impersonate', function (
    Request $request,
    User $user,
    \Philwamba\SecureImpersonation\ImpersonationManager $manager,
) {
    $validated = $request->validate([
        'reason' => ['required', 'string', 'min:10', 'max:500'],
    ]);

    return $manager->start($request, $user, $validated['reason']);
})->middleware(['auth', 'password.confirm', 'throttle:6,1']);

Route::post('/impersonation/stop', function (
    Request $request,
    \Philwamba\SecureImpersonation\ImpersonationManager $manager,
) {
    $manager->stop($request);

    return response()->noContent();
})->middleware('auth');
```

Starting and stopping regenerate the session identifier and clear the password-confirmation timestamp.

## Read-only protection

Apply `secure-impersonation.guard` after session authentication to the entire authenticated application. It rejects non-safe HTTP methods during impersonation and revalidates the original operator on every request.

```php
Route::middleware(['auth:sanctum', 'secure-impersonation.guard'])->group(function () {
    // Authenticated routes
});
```

GET routes that expose exports, downloads, attachments, protected media, billing, session management or other sensitive resources must additionally use:

```php
Route::get('/reports/export', ExportReportController::class)
    ->middleware('secure-impersonation.protect');
```

## Tenant or institution locking

Bind an `ImpersonationContext` implementation to capture a tenant, institution or access-scope identifier when impersonation starts and compare it on every request. The default context implementation captures nothing and always matches.

## Events and auditing

The package dispatches:

- `ImpersonationStarted`
- `ImpersonationEnded`
- `ImpersonatedRequestBlocked`
- `ImpersonatedRequestViewed` when `audit_views` is enabled

Applications should listen to these events and write them to their existing audit system. Never record passwords, session cookies, CSRF tokens, access tokens, complete request bodies or downloaded file contents.

## Configuration

```env
SECURE_IMPERSONATION_GUARD=web
SECURE_IMPERSONATION_DURATION_MINUTES=30
```

The duration has a minimum of five minutes. The package enforces an absolute server-side expiry and cancels the request that discovers expiry, preventing it from being replayed automatically as the restored administrator.

## Testing

```bash
composer quality
composer audit --locked
```

## Security

Please see [SECURITY.md](SECURITY.md). Do not publicly disclose a suspected impersonation bypass before a fix is available.
