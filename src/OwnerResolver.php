<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\Contracts\HasApiTokens;

/**
 * How an app names the owner a client's tokens act as, for
 * `oauth:client --owner=<reference>`.
 */
interface OwnerResolver
{
    /**
     * The owner the reference names, or null when there is none.
     */
    public function resolveOwner(string $reference): (Model&HasApiTokens)|null;
}
