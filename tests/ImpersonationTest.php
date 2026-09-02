<?php

namespace Philwamba\SecureImpersonation\Tests;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Philwamba\SecureImpersonation\Contracts\ImpersonationAuthorizer;
use Philwamba\SecureImpersonation\ImpersonationManager;
use Philwamba\SecureImpersonation\Middleware\GuardImpersonation;
use Philwamba\SecureImpersonation\Middleware\ProtectFromImpersonation;
use Philwamba\SecureImpersonation\Models\Impersonation;
use Philwamba\SecureImpersonation\Support\DenyAllAuthorizer;
use Philwamba\SecureImpersonation\Tests\Fixtures\User;

final class ImpersonationTest extends TestCase
{
    public function test_it_rotates_identity_and_restores_the_original_user(): void
    {
        [$administrator, $teacher] = $this->users();
        $request = $this->requestAs($administrator);
        $originalSessionId = $request->session()->getId();

        $record = $this->manager()->start($request, $teacher, 'Investigating an access problem.');

        self::assertSame($teacher->getKey(), Auth::id());
        self::assertNotSame($originalSessionId, $request->session()->getId());
        self::assertNull($record->ended_at);
        self::assertSame('Investigating an access problem.', $record->reason);

        $impersonatedSessionId = $request->session()->getId();
        $this->manager()->stop($request);

        self::assertSame($administrator->getKey(), Auth::id());
        self::assertNotSame($impersonatedSessionId, $request->session()->getId());
        self::assertNotNull($record->fresh()->ended_at);
    }

    public function test_default_authorizer_denies_impersonation(): void
    {
        [$administrator, $teacher] = $this->users();
        $request = $this->requestAs($administrator);
        $this->app->instance(ImpersonationAuthorizer::class, new DenyAllAuthorizer);
        $this->app->forgetInstance(ImpersonationManager::class);

        $this->expectException(AuthorizationException::class);
        $this->manager()->start($request, $teacher, 'Attempting an unauthorized session.');
    }

    public function test_guard_blocks_mutations_and_protected_get_requests(): void
    {
        [$administrator, $teacher] = $this->users();
        $request = $this->requestAs($administrator, 'POST', '/records');
        $this->manager()->start($request, $teacher, 'Checking a reported permissions problem.');

        $guardResponse = $this->app->make(GuardImpersonation::class)
            ->handle($request, fn () => response()->json(['ok' => true]));
        self::assertSame(403, $guardResponse->getStatusCode());

        $getRequest = $this->requestWithCurrentSession('GET', '/export');
        $protectedResponse = $this->app->make(ProtectFromImpersonation::class)
            ->handle($getRequest, fn () => response()->json(['ok' => true]));
        self::assertSame(403, $protectedResponse->getStatusCode());
    }

    public function test_expired_impersonation_is_ended_without_replaying_the_request_as_admin(): void
    {
        [$administrator, $teacher] = $this->users();
        $request = $this->requestAs($administrator, 'GET', '/sensitive');
        $record = $this->manager()->start($request, $teacher, 'Checking an expiring support session.');
        $record->forceFill(['expires_at' => now()->subMinute()])->save();

        $called = false;
        $response = $this->app->make(GuardImpersonation::class)->handle(
            $request,
            function () use (&$called) {
                $called = true;

                return response()->json(['ok' => true]);
            },
        );

        self::assertSame(409, $response->getStatusCode());
        self::assertFalse($called);
        self::assertSame($administrator->getKey(), Auth::id());
        self::assertSame('expired', Impersonation::query()->firstOrFail()->ended_reason);
    }

    /** @return array{User, User} */
    private function users(): array
    {
        return [
            User::query()->create([
                'name' => 'Super Administrator',
                'email' => 'admin@example.test',
                'password' => bcrypt('password'),
            ]),
            User::query()->create([
                'name' => 'Teacher',
                'email' => 'teacher@example.test',
                'password' => bcrypt('password'),
            ]),
        ];
    }

    private function requestAs(User $user, string $method = 'POST', string $uri = '/impersonate'): Request
    {
        Auth::guard('web')->login($user);

        $request = Request::create($uri, $method);
        $session = $this->app['session']->driver();
        $session->start();
        $request->setLaravelSession($session);
        $request->setUserResolver(fn () => Auth::guard('web')->user());

        return $request;
    }

    private function requestWithCurrentSession(string $method, string $uri): Request
    {
        $request = Request::create($uri, $method);
        $request->setLaravelSession($this->app['session']->driver());
        $request->setUserResolver(fn () => Auth::guard('web')->user());

        return $request;
    }

    private function manager(): ImpersonationManager
    {
        return $this->app->make(ImpersonationManager::class);
    }
}
