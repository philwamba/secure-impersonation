<?php

namespace Philwamba\SecureImpersonation\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Impersonation extends Model
{
    use HasUuids;

    protected $guarded = ['id', 'created_at', 'updated_at'];

    public function getTable(): string
    {
        return (string) config('secure-impersonation.table', 'secure_impersonations');
    }

    protected function casts(): array
    {
        return [
            'context' => 'array',
            'started_at' => 'immutable_datetime',
            'expires_at' => 'immutable_datetime',
            'ended_at' => 'immutable_datetime',
        ];
    }
}
