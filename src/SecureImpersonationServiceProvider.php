<?php

namespace Philwamba\SecureImpersonation;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\Contracts\ImpersonationContext;
use Philwamba\SecureImpersonation\Middleware\GuardImpersonation;
use Philwamba\SecureImpersonation\Middleware\ProtectFromImpersonation;
use Philwamba\SecureImpersonation\Support\DenyAllAuthorizer;
use Philwamba\SecureImpersonation\Support\NullImpersonationContext;

final class SecureImpersonationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/secure-impersonation.php',
            'secure-impersonation',
        );

        $this->app->bindIf(ImpersonationAuthorizer::class, DenyAllAuthorizer::class);
        $this->app->bindIf(ImpersonationContext::class, NullImpersonationContext::class);
        $this->app->singleton(ImpersonationManager::class);
    }

    public function boot(Router $router): void
    {
        $router->aliasMiddleware('secure-impersonation.guard', GuardImpersonation::class);
        $router->aliasMiddleware('secure-impersonation.protect', ProtectFromImpersonation::class);

        $this->publishes([
            __DIR__.'/../config/secure-impersonation.php' => config_path('secure-impersonation.php'),
        ], 'secure-impersonation-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/create_secure_impersonations_table.php.stub' => database_path('migrations/create_secure_impersonations_table.php'),
        ], 'secure-impersonation-migrations');
    }
}
