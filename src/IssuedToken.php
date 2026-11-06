<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

/**
 * What a successful client-credentials request gets back.
 */
final class IssuedToken
{
    /**
     * @param  list<string>  $abilities
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly int $expiresIn,
        public readonly array $abilities,
    ) {}
}
