<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials\Tests;

use Amfortas\ClientCredentials\OauthClient;
use Amfortas\ClientCredentials\Tests\Fixtures\Operator;
use Amfortas\ClientCredentials\Tests\Fixtures\OperatorsByEmail;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Testing\PendingCommand;
use InvalidArgumentException;
use Laravel\Sanctum\PersonalAccessToken;
use PHPUnit\Framework\Attributes\Test;

final class ManageOauthClientTest extends TestCase
{
    #[Test]
    public function createsAClientAndPrintsItsSecretOnce(): void
    {
        // Read what the command printed, which a mocked console would swallow.
        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('oauth:client', [
            'client_id' => 'broker',
            '--no-owner' => true,
            '--abilities' => 'reports:read,reports:write',
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit);
        $client = OauthClient::query()->where('client_id', 'broker')->firstOrFail();
        $this->assertNull($client->owner_type);
        $this->assertSame(['reports:read', 'reports:write'], $client->allowed_abilities);
        $this->assertNull($client->revoked_at);

        $secret = $this->secretIn($output);
        $this->assertTrue(OauthClient::authenticate('broker', $secret) !== null);
        $this->assertStringNotContainsString($secret, $client->secret_hash);
        $this->assertStringStartsWith('$argon2id$', $client->secret_hash);
    }

    #[Test]
    public function createsAClientWhoseTokensActAsTheOwnerTheAppResolves(): void
    {
        $this->resolveOwnersByEmail();
        $operator = Operator::query()->create(['email' => 'ops@example.test']);

        $this->oauthClient([
            'client_id' => 'broker',
            '--owner' => 'ops@example.test',
            '--abilities' => 'reports:read',
        ])->assertSuccessful();

        $client = OauthClient::query()->firstOrFail();
        $this->assertTrue($client->owner?->is($operator));
    }

    #[Test]
    public function refusesAnOwnerTheAppCannotResolve(): void
    {
        $this->resolveOwnersByEmail();

        $this->oauthClient([
            'client_id' => 'broker',
            '--owner' => 'nobody@example.test',
            '--abilities' => 'reports:read',
        ])->assertFailed();

        $this->assertSame(0, OauthClient::query()->count());
    }

    #[Test]
    public function refusesAnOwnerWhenTheAppNamesNoResolver(): void
    {
        Operator::query()->create(['email' => 'ops@example.test']);

        $this->oauthClient([
            'client_id' => 'broker',
            '--owner' => 'ops@example.test',
            '--abilities' => 'reports:read',
        ])->assertFailed();

        $this->assertSame(0, OauthClient::query()->count());
    }

    #[Test]
    public function creatingNamesAnOwnerOrSaysThereIsNone(): void
    {
        $this->resolveOwnersByEmail();
        Operator::query()->create(['email' => 'ops@example.test']);

        $this->oauthClient(['client_id' => 'broker', '--abilities' => 'reports:read'])->assertFailed();
        $this->oauthClient([
            'client_id' => 'broker', '--owner' => 'ops@example.test', '--no-owner' => true, '--abilities' => 'reports:read',
        ])->assertFailed();

        $this->assertSame(0, OauthClient::query()->count());
    }

    #[Test]
    public function aClientThatCannotBeSavedWhollyLeavesNoRow(): void
    {
        // An app that enforces a morph map without naming the client
        // cannot hold its tokens; the client must not half exist.
        Relation::enforceMorphMap(['operator' => Operator::class]);
        $refused = null;

        try {
            OauthClient::register(null, 'broker', ['reports:read']);
        } catch (ClassMorphViolationException $e) {
            $refused = $e;
        } finally {
            Relation::requireMorphMap(false);
            Relation::morphMap([], false);
        }

        $this->assertNotNull($refused);
        $this->assertSame(0, OauthClient::query()->count());
    }

    #[Test]
    public function theMigrationIsPublishedWithADatePrefix(): void
    {
        $before = glob(database_path('migrations/*_create_oauth_clients_table.php')) ?: [];

        $this->oauthPublish();

        $published = array_values(array_diff(glob(database_path('migrations/*_create_oauth_clients_table.php')) ?: [], $before));
        foreach ($published as $file) {
            unlink($file);
        }
        $this->assertCount(1, $published);
        $this->assertMatchesRegularExpression('/\/\d{4}_\d{2}_\d{2}_\d{6}_create_oauth_clients_table\.php$/', $published[0]);
    }

    #[Test]
    public function refusesAnExistingClientWithoutRotate(): void
    {
        $this->oauthClient(['client_id' => 'broker', '--no-owner' => true, '--abilities' => 'reports:read'])->assertSuccessful();
        $hash = OauthClient::query()->firstOrFail()->secret_hash;

        $this->oauthClient(['client_id' => 'broker', '--no-owner' => true, '--abilities' => 'reports:read'])->assertFailed();

        $this->assertSame($hash, OauthClient::query()->firstOrFail()->secret_hash);
    }

    #[Test]
    public function rotateReplacesTheSecretAndKillsLiveTokens(): void
    {
        [$client, $old] = OauthClient::register(null, 'broker', ['reports:read']);
        $client->issueToken(['reports:read'], CarbonImmutable::now()->addHour());

        // Read what the command printed, which a mocked console would swallow.
        $this->withoutMockingConsoleOutput();
        $exit = Artisan::call('oauth:client', ['client_id' => 'broker', '--rotate' => true]);
        $secret = $this->secretIn(Artisan::output());

        $this->assertSame(0, $exit);
        $client->refresh();
        $this->assertFalse(OauthClient::authenticate('broker', $old) !== null);
        $this->assertTrue(OauthClient::authenticate('broker', $secret) !== null);
        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(['reports:read'], $client->allowed_abilities);
    }

    #[Test]
    public function grantAddsAbilitiesAndKeepsTheSecretAndLiveTokens(): void
    {
        [$client, $secret] = OauthClient::register(null, 'broker', ['reports:read']);
        $client->issueToken(['reports:read'], CarbonImmutable::now()->addHour());

        $this->oauthClient(['client_id' => 'broker', '--grant' => 'reports:write, reports:read'])
            ->assertSuccessful()
            ->doesntExpectOutputToContain('secret:');

        $client->refresh();
        $this->assertSame(['reports:read', 'reports:write'], $client->allowed_abilities);
        $this->assertTrue(OauthClient::authenticate('broker', $secret) !== null);
        $this->assertSame(1, PersonalAccessToken::query()->count());
    }

    #[Test]
    public function grantRefusesARevokedClientTheWildcardOrNothing(): void
    {
        [$client] = OauthClient::register(null, 'broker', ['reports:read']);

        foreach (['*', ' , '] as $abilities) {
            $this->oauthClient(['client_id' => 'broker', '--grant' => $abilities])->assertFailed();
        }
        $client->revoke();
        $this->oauthClient(['client_id' => 'broker', '--grant' => 'reports:write'])->assertFailed();
        $this->oauthClient(['client_id' => 'nobody', '--grant' => 'reports:write'])->assertFailed();

        $this->assertSame(['reports:read'], $client->refresh()->allowed_abilities);
    }

    #[Test]
    public function revokeMarksTheClientAndKillsOnlyItsOwnLiveTokens(): void
    {
        $operator = Operator::query()->create(['email' => 'ops@example.test']);
        [$client] = OauthClient::register($operator, 'broker', ['reports:read']);
        $client->issueToken(['reports:read'], CarbonImmutable::now()->addHour());
        // A token of the same owner that this client did not issue survives.
        $operator->createToken('hand-made', ['reports:read']);

        $this->oauthClient(['client_id' => 'broker', '--revoke' => true])->assertSuccessful();

        $this->assertNotNull($client->refresh()->revoked_at);
        $this->assertSame(['hand-made'], $operator->tokens()->pluck('name')->all());
    }

    #[Test]
    public function refusesTheWildcardAbilityOrNoAbilities(): void
    {
        $this->oauthClient(['client_id' => 'broker', '--no-owner' => true, '--abilities' => 'reports:read,*'])->assertFailed();
        $this->oauthClient(['client_id' => 'broker', '--no-owner' => true, '--abilities' => ''])->assertFailed();

        $this->assertSame(0, OauthClient::query()->count());
    }

    #[Test]
    public function rotateRefusesARevokedClient(): void
    {
        [$client] = OauthClient::register(null, 'broker', ['reports:read']);
        $client->revoke();
        $hash = $client->secret_hash;

        $this->oauthClient(['client_id' => 'broker', '--rotate' => true])->assertFailed();

        $this->assertSame($hash, $client->refresh()->secret_hash);
    }

    #[Test]
    public function refusesOptionsThatDoNotBelongTogether(): void
    {
        [$client] = OauthClient::register(null, 'broker', ['reports:read']);

        foreach ([
            ['--rotate' => true, '--revoke' => true],
            ['--rotate' => true, '--abilities' => 'reports:write'],
            ['--rotate' => true, '--grant' => 'reports:write'],
            ['--grant' => 'reports:write', '--abilities' => 'reports:write'],
            ['--revoke' => true, '--owner' => 'ops@example.test'],
            ['--rotate' => true, '--no-owner' => true],
        ] as $options) {
            $this->oauthClient(['client_id' => 'broker', ...$options])->assertFailed();
        }

        $client->refresh();
        $this->assertNull($client->revoked_at);
        $this->assertSame(['reports:read'], $client->allowed_abilities);
    }

    #[Test]
    public function aTokenCannotCarryAnAbilityTheClientIsNotAllowed(): void
    {
        [$client] = OauthClient::register(null, 'broker', ['reports:read']);

        $this->expectException(InvalidArgumentException::class);
        $client->issueToken(['reports:read', 'reports:publish'], CarbonImmutable::now()->addHour());
    }

    #[Test]
    public function theAbilityRuleHoldsForEverySaveNotOnlyTheCommand(): void
    {
        [$client] = OauthClient::register(null, 'broker', ['reports:read']);

        $client->allowed_abilities = ['*'];
        $this->expectException(InvalidArgumentException::class);
        $client->save();
    }

    /**
     * @param  array<string, string|bool>  $parameters
     */
    private function oauthClient(array $parameters): PendingCommand
    {
        $command = $this->artisan('oauth:client', $parameters);
        $this->assertInstanceOf(PendingCommand::class, $command);

        return $command;
    }

    private function oauthPublish(): void
    {
        $command = $this->artisan('vendor:publish', ['--tag' => 'client-credentials-migrations']);
        $this->assertInstanceOf(PendingCommand::class, $command);
        $command->assertSuccessful();
    }

    private function resolveOwnersByEmail(): void
    {
        $this->app?->make(Repository::class)->set('client-credentials.owner_resolver', OperatorsByEmail::class);
    }

    private function secretIn(string $output): string
    {
        if (preg_match('/^secret: (\S+)$/m', $output, $match) !== 1) {
            self::fail("no secret line in:\n{$output}");
        }

        return $match[1];
    }
}
