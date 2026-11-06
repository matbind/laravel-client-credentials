<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * A refused token request, rendered as RFC 6749 §5.2 says: a JSON body
 * with one of the registered `error` codes, never cached. The
 * description is fixed text written here, never anything the caller sent.
 * It is the answer to a caller, not a fault of the app, so it is never
 * reported or logged.
 */
final class OAuthError extends RuntimeException
{
    /**
     * @param  array<string, string>  $headers
     */
    private function __construct(
        public readonly string $error,
        string $description,
        public readonly int $status,
        private readonly array $headers = [],
    ) {
        parent::__construct($description);
    }

    public static function invalidRequest(string $description): self
    {
        return new self('invalid_request', $description, 400);
    }

    /**
     * Unknown client, wrong secret, revoked client or no credentials: one
     * answer for all, so a caller learns nothing about which it was.
     */
    public static function invalidClient(): self
    {
        return new self('invalid_client', 'client authentication failed', 401, [
            'WWW-Authenticate' => 'Basic realm="'.self::realm().'"',
        ]);
    }

    /**
     * Not one of §5.2's cases; 429 so a client backs off and retries
     * rather than treating it as a wrong secret.
     */
    public static function tooManyFailures(int $retryAfterSeconds): self
    {
        return new self('invalid_client', 'too many failed attempts; retry later', 429, [
            'Retry-After' => (string) $retryAfterSeconds,
        ]);
    }

    public static function invalidScope(): self
    {
        return new self('invalid_scope', 'scope exceeds what this client is allowed', 400);
    }

    public static function unsupportedGrantType(): self
    {
        return new self('unsupported_grant_type', 'only client_credentials is supported', 400);
    }

    public function render(): JsonResponse
    {
        return new JsonResponse(
            ['error' => $this->error, 'error_description' => $this->getMessage()],
            $this->status,
            $this->headers + ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'],
        );
    }

    /**
     * Stops Laravel's handler from reporting it.
     */
    public function report(): void {}

    /** The app's name, which a refused client is told as the realm. */
    private static function realm(): string
    {
        $realm = config('app.name');

        return is_string($realm) && $realm !== '' ? str_replace('"', '', $realm) : 'laravel';
    }
}
