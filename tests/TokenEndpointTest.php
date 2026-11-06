<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials\Tests;

use Amfortas\ClientCredentials\OauthClient;
use Amfortas\ClientCredentials\Tests\Fixtures\Operator;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\PersonalAccessToken;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * The OAuth 2.0 client-credentials endpoint (RFC 6749 §4.4). The client
 * row is the one place a client's abilities are written down: an empty
 * scope asks for all of them, a non-empty one for a subset.
 */
final class TokenEndpointTest extends TestCase
{
    private const ALLOWED = ['reports:read', 'reports:write', 'reports:publish'];

    #[Test]
    public function issuesAnHourLongBearerTokenOwnedByTheClientItself(): void
    {
        [$client, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $response = $this->requestToken(['client_secret' => $secret]);

        $response->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertHeader('Pragma', 'no-cache')
            ->assertJsonPath('token_type', 'Bearer')
            ->assertJsonPath('expires_in', 3600);
        $token = $this->tokenOf($response);
        $this->assertSame('oauth:broker', $token->name);
        $this->assertTrue($token->tokenable?->is($client));
        $this->assertEqualsWithDelta(now()->addHour()->getTimestamp(), $token->expires_at?->getTimestamp(), 5);
    }

    #[Test]
    public function theTokensOfAClientWithAnOwnerActAsTheOwner(): void
    {
        $operator = Operator::query()->create(['email' => 'ops@example.test']);
        [, $secret] = OauthClient::register($operator, 'broker', self::ALLOWED);

        $token = $this->tokenOf($this->requestToken(['client_secret' => $secret]));

        $this->assertTrue($token->tokenable?->is($operator));
    }

    #[Test]
    public function aTokenOwnedByItsClientAuthenticatesAsTheClient(): void
    {
        [$client, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);
        $token = $this->accessToken($this->requestToken(['client_secret' => $secret]));

        $this->withToken($token)->get('/whoami')->assertOk()->assertSeeText((string) $client->id);
    }

    #[Test]
    public function aClientWhoseOwnerIsGoneIsInvalidClient(): void
    {
        $operator = Operator::query()->create(['email' => 'ops@example.test']);
        [, $secret] = OauthClient::register($operator, 'broker', self::ALLOWED);
        $operator->delete();

        $this->assertOAuthError($this->requestToken(['client_secret' => $secret]), 401, 'invalid_client');
        $this->assertSame(0, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function aRefusedRequestIsAnsweredNotReported(): void
    {
        // Logged, a refusal's trace would carry the secret the caller sent.
        $log = Log::spy();
        OauthClient::register(null, 'broker', ['reports:read']);

        $this->requestToken(['client_secret' => 'wrong'])->assertUnauthorized();
        $this->requestToken(['client_id' => 'nobody', 'client_secret' => 'wrong'])->assertUnauthorized();
        $this->requestToken(['client_secret' => 'wrong', 'scope' => ['a']])->assertStatus(400);

        $log->shouldNotHaveReceived('error');
    }

    #[Test]
    public function anUnknownClientIsCheckedAgainstAStoredDummyHash(): void
    {
        // A dummy hash made per request would make an unknown id slower to
        // refuse than a known one.
        $this->requestToken(['client_id' => 'nobody', 'client_secret' => 'whatever'])->assertUnauthorized();

        $this->assertTrue(Cache::has('client-credentials:dummy-hash'));
    }

    #[Test]
    public function issuingATokenRemovesTheClientsExpiredOnes(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);
        $this->requestToken(['client_secret' => $secret])->assertOk();
        $this->travel(2)->hours();

        $this->requestToken(['client_secret' => $secret])->assertOk();

        $this->assertSame(1, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function credentialsInHttpBasicAreReadWhateverTheSchemesCase(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $this->withHeader('Authorization', 'basic '.base64_encode('broker:'.$secret))
            ->post(self::TOKEN_PATH, ['grant_type' => 'client_credentials'])
            ->assertOk();
    }

    #[Test]
    public function aListWhereAStringBelongsIsInvalidRequest(): void
    {
        foreach (['client_id', 'client_secret', 'scope', 'grant_type'] as $field) {
            $response = $this->post(self::TOKEN_PATH, [
                'grant_type' => 'client_credentials',
                'client_id' => 'broker',
                'client_secret' => 'x',
                $field => ['a'],
            ]);
            $this->assertOAuthError($response, 400, 'invalid_request');
        }
    }

    #[Test]
    public function anEmptyScopeGrantsEveryAllowedAbility(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $response = $this->requestToken(['client_secret' => $secret, 'scope' => '']);

        $response->assertOk()->assertJsonPath('scope', implode(' ', self::ALLOWED));
        $this->assertSame(self::ALLOWED, $this->tokenOf($response)->abilities);
    }

    #[Test]
    public function anOmittedScopeGrantsEveryAllowedAbility(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $this->assertSame(self::ALLOWED, $this->tokenOf($this->requestToken(['client_secret' => $secret]))->abilities);
    }

    #[Test]
    public function aSubsetScopeGrantsOnlyThatSubset(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $response = $this->requestToken(['client_secret' => $secret, 'scope' => 'reports:write  reports:read']);

        $response->assertOk()->assertJsonPath('scope', 'reports:write reports:read');
        $this->assertSame(['reports:write', 'reports:read'], $this->tokenOf($response)->abilities);
    }

    #[Test]
    public function aScopeBeyondTheAllowedSetIsInvalidScope(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', ['reports:read']);

        $response = $this->requestToken(['client_secret' => $secret, 'scope' => 'reports:read reports:publish']);

        $this->assertOAuthError($response, 400, 'invalid_scope');
        $this->assertSame(0, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function theTokenOpensTheRoutesItsAbilitiesCoverAndNoOthers(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', ['reports:read']);
        $token = $this->accessToken($this->requestToken(['client_secret' => $secret]));

        $this->withToken($token)->getJson('/reports')->assertOk();
        $this->withToken($token)->postJson('/reports/publish')->assertForbidden();
    }

    #[Test]
    public function theTokenStopsWorkingAfterAnHour(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', ['reports:read']);
        $token = $this->accessToken($this->requestToken(['client_secret' => $secret]));
        $this->withToken($token)->getJson('/reports')->assertOk();
        $this->app?->make('auth')->forgetGuards();

        $this->travel(61)->minutes();

        $this->withToken($token)->getJson('/reports')->assertUnauthorized();
    }

    #[Test]
    public function aRevokedClientIsInvalidClient(): void
    {
        [$client, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);
        $client->revoke();

        $this->assertOAuthError($this->requestToken(['client_secret' => $secret]), 401, 'invalid_client');
    }

    #[Test]
    public function revokingAClientKillsTheTokensItAlreadyHolds(): void
    {
        [$client, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);
        $this->requestToken(['client_secret' => $secret])->assertOk();

        $client->revoke();

        $this->assertSame(0, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function aWrongSecretIsInvalidClient(): void
    {
        OauthClient::register(null, 'broker', self::ALLOWED);

        $this->assertOAuthError($this->requestToken(['client_secret' => 'not-the-secret']), 401, 'invalid_client');
        $this->assertSame(0, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function anUnknownClientIsInvalidClient(): void
    {
        $this->assertOAuthError(
            $this->requestToken(['client_id' => 'nobody', 'client_secret' => 'whatever']),
            401,
            'invalid_client',
        );
    }

    #[Test]
    public function missingCredentialsAreInvalidClient(): void
    {
        $this->assertOAuthError(
            $this->post(self::TOKEN_PATH, ['grant_type' => 'client_credentials']),
            401,
            'invalid_client',
        );
    }

    #[Test]
    public function credentialsInHttpBasicAreAccepted(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $this->withHeader('Authorization', 'Basic '.base64_encode('broker:'.$secret))
            ->post(self::TOKEN_PATH, ['grant_type' => 'client_credentials'])
            ->assertOk()
            ->assertJsonPath('token_type', 'Bearer');
    }

    #[Test]
    public function credentialsInBothBasicAndBodyAreInvalidRequest(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $response = $this->withHeader('Authorization', 'Basic '.base64_encode('broker:'.$secret))
            ->post(self::TOKEN_PATH, [
                'grant_type' => 'client_credentials',
                'client_id' => 'broker',
                'client_secret' => $secret,
            ]);

        $this->assertOAuthError($response, 400, 'invalid_request');
    }

    #[Test]
    public function aSecretInTheQueryStringIsNotRead(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $response = $this->post(
            self::TOKEN_PATH.'?client_id=broker&client_secret='.urlencode($secret),
            ['grant_type' => 'client_credentials'],
        );

        $this->assertOAuthError($response, 401, 'invalid_client');
    }

    #[Test]
    public function anyOtherGrantTypeIsUnsupported(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        $this->assertOAuthError(
            $this->requestToken(['client_secret' => $secret, 'grant_type' => 'password']),
            400,
            'unsupported_grant_type',
        );
    }

    #[Test]
    public function aMissingGrantTypeIsInvalidRequest(): void
    {
        $this->assertOAuthError(
            $this->post(self::TOKEN_PATH, ['client_id' => 'a', 'client_secret' => 'b']),
            400,
            'invalid_request',
        );
    }

    #[Test]
    public function repeatedBadSecretsAreRateLimitedPerClient(): void
    {
        [, $secret] = OauthClient::register(null, 'broker', self::ALLOWED);

        for ($i = 0; $i < 10; $i++) {
            $this->requestToken(['client_secret' => 'wrong'])->assertUnauthorized();
        }

        // Once limited, even the right secret waits: answering it would
        // tell a guesser which of its tries was right.
        $limited = $this->requestToken(['client_secret' => $secret]);
        $limited->assertStatus(429)->assertHeader('Retry-After');
        $this->assertSame('invalid_client', $limited->json('error'));

        // Another client is not held up by this one's failures, nor is
        // this one from another address: the limit stops guessing, and a
        // guesser cannot lock the client out for everyone.
        OauthClient::register(null, 'other-client', self::ALLOWED);
        $this->requestToken(['client_id' => 'other-client', 'client_secret' => 'wrong'])->assertUnauthorized();
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.7'])
            ->requestToken(['client_secret' => $secret])
            ->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1']);

        $this->travel(61)->seconds();
        $this->requestToken(['client_secret' => $secret])->assertOk();
    }

    /**
     * @param  array<string, string|list<string>>  $params
     * @return TestResponse<Response>
     */
    private function requestToken(array $params): TestResponse
    {
        return $this->post(self::TOKEN_PATH, $params + [
            'grant_type' => 'client_credentials',
            'client_id' => 'broker',
        ]);
    }

    /**
     * @param  TestResponse<Response>  $response
     */
    private function accessToken(TestResponse $response): string
    {
        $token = $response->json('access_token');
        $this->assertIsString($token);

        return $token;
    }

    /**
     * @param  TestResponse<Response>  $response
     */
    private function tokenOf(TestResponse $response): PersonalAccessToken
    {
        $token = PersonalAccessToken::findToken($this->accessToken($response));
        $this->assertNotNull($token);

        return $token;
    }

    /**
     * RFC 6749 §5.2: a JSON body whose `error` is one of the registered
     * codes, never cached, and no more than that.
     *
     * @param  TestResponse<Response>  $response
     */
    private function assertOAuthError(TestResponse $response, int $status, string $error): void
    {
        $response->assertStatus($status)
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertHeader('Pragma', 'no-cache');
        $this->assertSame($error, $response->json('error'));
        $body = $response->json();
        $this->assertIsArray($body);
        $this->assertSame([], array_diff(array_keys($body), ['error', 'error_description']));
        if ($status === 401) {
            $response->assertHeader('WWW-Authenticate', 'Basic realm="test-app"');
        }
    }
}
