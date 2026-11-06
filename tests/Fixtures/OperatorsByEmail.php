<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials\Tests\Fixtures;

use Amfortas\ClientCredentials\OwnerResolver;

/**
 * Finds the operator `oauth:client --owner=` names, by email.
 */
final class OperatorsByEmail implements OwnerResolver
{
    public function resolveOwner(string $reference): ?Operator
    {
        return Operator::query()->where('email', $reference)->first();
    }
}
