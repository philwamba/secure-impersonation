<?php

namespace Philwamba\SecureImpersonation\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

final class User extends Authenticatable
{
    protected $guarded = [];

    protected $hidden = ['password', 'remember_token'];
}
