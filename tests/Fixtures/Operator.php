<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\Contracts\HasApiTokens as HoldsTokens;
use Laravel\Sanctum\HasApiTokens;

/**
 * Someone the tokens of a client can act as, as an app's user would be.
 *
 * @property int $id
 * @property string $email
 */
final class Operator extends Model implements HoldsTokens
{
    use HasApiTokens;

    protected $fillable = ['email'];
}
