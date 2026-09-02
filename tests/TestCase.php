<?php

namespace Philwamba\SecureImpersonation\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\ImpersonationManager;
use Philwamba\SecureImpersonation\SecureImpersonationServiceProvider;
use Philwamba\SecureImpersonation\Tests\Fixtures\AllowAllAuthorizer;
use Philwamba\SecureImpersonation\Tests\Fixtures\User;

abstract class TestCase extends Orchestra
{
    protected AllowAllAuthorizer $authorizer;

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });

        $migration = require __DIR__.'/../database/migrations/create_secure_impersonations_table.php.stub';
        $migration->up();

        $this->authorizer = new AllowAllAuthorizer;
        $this->app->instance(ImpersonationAuthorizer::class, $this->authorizer);
        $this->app->forgetInstance(ImpersonationManager::class);
    }

    protected function getPackageProviders($app): array
    {
        return [SecureImpersonationServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', [
            'driver' => 'session',
            'provider' => 'users',
        ]);
        $app['config']->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model' => User::class,
        ]);
        $app['config']->set('session.driver', 'array');
    }
}
