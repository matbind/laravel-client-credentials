<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\RateLimiter;
use SensitiveParameter;

/**
 * The OAuth 2.0 client-credentials grant (RFC 6749 §4.4): a client
 * proves its secret and gets back a Sanctum token that expires in an
 * hour, carrying the abilities it asked for. Sanctum's `auth:sanctum`
 * and `abilities:` middleware then treat it like any other token.
 *
 * Scope has one source of truth, the client row: an empty scope asks
 * for every allowed ability, a non-empty one must be a subset of them.
 * A caller therefore never has to repeat the ability list.
 *
 * Wrong secrets are rate-limited per client_id and caller address, known
 * id or not. While limited, even the right secret is refused there, so a
 * guesser cannot tell from the answer which of its tries was right, and
 * one cannot lock the client out for every other address. The limit
 * stops guessing at one client; spreading guesses over many ids costs a
 * hash each, which the app's own throttle on the route bounds.
 */
final class ClientCredentialsGrant
{
    public const TOKEN_LIFETIME_SECONDS = 3600;

    private const MAX_FAILURES = 10;

    private const FAILURE_WINDOW_SECONDS = 60;

    /**
     * @param  string  $scope  Space-delimited abilities; empty for all the client may have.
     * @param  string  $caller  The address the request came from.
     *
     * @throws OAuthError
     */
    public function issue(string $clientId, #[SensitiveParameter] string $secret, string $scope, string $caller): IssuedToken
    {
        $throttleKey = 'oauth-token:'.sha1($clientId."\0".$caller);
        if (RateLimiter::tooManyAttempts($throttleKey, self::MAX_FAILURES)) {
            throw OAuthError::tooManyFailures(RateLimiter::availableIn($throttleKey));
        }

        $client = OauthClient::authenticate($clientId, $secret);
        if ($client === null) {
            RateLimiter::hit($throttleKey, self::FAILURE_WINDOW_SECONDS);
            throw OAuthError::invalidClient();
        }

        $abilities = $this->grantedAbilities($client, $scope);
        $token = $client->issueToken($abilities, CarbonImmutable::now()->addSeconds(self::TOKEN_LIFETIME_SECONDS));

        return new IssuedToken($token->plainTextToken, self::TOKEN_LIFETIME_SECONDS, $abilities);
    }

    /**
     * @return list<string>
     *
     * @throws OAuthError
     */
    private function grantedAbilities(OauthClient $client, string $scope): array
    {
        $requested = array_values(array_unique(preg_split('/ +/', trim($scope), flags: PREG_SPLIT_NO_EMPTY) ?: []));
        if ($requested === []) {
            return $client->allowed_abilities;
        }

        if (array_diff($requested, $client->allowed_abilities) !== []) {
            throw OAuthError::invalidScope();
        }

        return $requested;
    }
}
