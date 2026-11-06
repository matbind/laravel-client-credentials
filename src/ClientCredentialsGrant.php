<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Carbon\CarbonImmutable;
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
 * Guessing is bounded by the route's limiter, by address (see
 * [TokenController::route]); a generated secret is far too long to guess
 * within it. There is no limit per client, which would let anyone who
 * knows a client id lock that client out.
 */
final class ClientCredentialsGrant
{
    /**
     * @param  string  $scope  Space-delimited abilities; empty for all the client may have.
     *
     * @throws OAuthError
     */
    public function issue(string $clientId, #[SensitiveParameter] string $secret, string $scope): IssuedToken
    {
        $client = OauthClient::authenticate($clientId, $secret);
        if ($client === null) {
            throw OAuthError::invalidClient();
        }

        $abilities = $this->grantedAbilities($client, $scope);
        $token = $client->issueToken($abilities, CarbonImmutable::now()->addSeconds(OauthClient::TOKEN_LIFETIME_SECONDS));

        return new IssuedToken($token->plainTextToken, OauthClient::TOKEN_LIFETIME_SECONDS, $abilities);
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
