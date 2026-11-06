<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The token endpoint, the HTTP side of [ClientCredentialsGrant]: reads
 * the grant type and client credentials the way RFC 6749 allows them to
 * arrive, and shapes the answer as §5.1 says. The app chooses its path:
 *
 *   Route::post('oauth/token', TokenController::class);
 *
 * Credentials come either in the form body or as HTTP Basic (§2.3.1),
 * never both and never in the query string, where they would land in
 * access logs.
 */
final class TokenController
{
    public function __invoke(Request $request, ClientCredentialsGrant $grant): JsonResponse
    {
        $grantType = $this->bodyString($request, 'grant_type');
        $scope = $this->bodyString($request, 'scope');
        if ($grantType === '') {
            throw OAuthError::invalidRequest('grant_type is required');
        }
        if ($grantType !== 'client_credentials') {
            throw OAuthError::unsupportedGrantType();
        }

        [$clientId, $secret] = $this->credentials($request);
        $issued = $grant->issue($clientId, $secret, $scope, (string) $request->ip());

        return new JsonResponse([
            'access_token' => $issued->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $issued->expiresIn,
            'scope' => implode(' ', $issued->abilities),
        ], 200, ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache']);
    }

    /**
     * @return array{0: string, 1: string}
     *
     * @throws OAuthError
     */
    private function credentials(Request $request): array
    {
        $inBody = $request->request->has('client_id') || $request->request->has('client_secret');
        $basic = $request->header('Authorization');
        // The scheme is case-insensitive (RFC 7235 §2.1).
        $inBasic = is_string($basic) && strncasecmp($basic, 'Basic ', 6) === 0;

        if ($inBody && $inBasic) {
            throw OAuthError::invalidRequest('send client credentials one way, not two');
        }

        if ($inBasic) {
            // §2.3.1: both parts are form-encoded before they are joined.
            $pair = explode(':', (string) base64_decode(substr($basic, 6), true), 2);

            return [urldecode($pair[0]), urldecode($pair[1] ?? '')];
        }

        return [$this->bodyString($request, 'client_id'), $this->bodyString($request, 'client_secret')];
    }

    /**
     * @throws OAuthError for a list or object where a string belongs
     */
    private function bodyString(Request $request, string $key): string
    {
        $value = $request->request->all()[$key] ?? '';
        if (! is_string($value)) {
            throw OAuthError::invalidRequest("{$key} must be a string");
        }

        return $value;
    }
}
