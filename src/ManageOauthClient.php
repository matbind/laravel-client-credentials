<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;
use LogicException;

/**
 * Create, rotate or revoke a client of the token endpoint, or grant an
 * existing one more abilities.
 *
 *   php artisan oauth:client broker --no-owner --abilities=reports:read,reports:write
 *   php artisan oauth:client broker --owner=ops@example.com --abilities=reports:read
 *   php artisan oauth:client broker --grant=reports:publish
 *   php artisan oauth:client broker --rotate
 *   php artisan oauth:client broker --revoke
 *
 * Creating says who the tokens act as: `--owner` names someone, through
 * the app's `client-credentials.owner_resolver`, and `--no-owner` makes
 * the client hold them itself; leaving both out is refused, so a
 * forgotten owner cannot quietly become none. Creating and rotating print the secret once, on a line of its
 * own (`secret: …`); it is not stored and cannot be shown again.
 * Creating an id that exists fails rather than rotating, so a re-run by
 * mistake does not cut off whoever holds the current secret. Granting
 * keeps the secret, so the client carries on and its next token may
 * carry the new ability. Options that do not belong together are refused
 * rather than ignored.
 */
final class ManageOauthClient extends Command
{
    protected $signature = 'oauth:client
        {client_id : The id the client sends with its secret}
        {--owner= : Who its tokens act as, as the app resolves it (create only)}
        {--no-owner : Its tokens act as the client itself (create only)}
        {--abilities= : Comma-separated abilities it may be granted (create only)}
        {--grant= : Comma-separated abilities to add to an existing client}
        {--rotate : Replace the secret and kill the live tokens}
        {--revoke : Refuse the client from now on and kill the live tokens}';

    protected $description = 'Create, rotate, revoke or grant abilities to an OAuth client-credentials client';

    public function handle(Container $container): int
    {
        $clientId = $this->stringArgument('client_id');
        $rotate = $this->option('rotate') === true;
        $revoke = $this->option('revoke') === true;
        $grant = $this->stringOption('grant');

        if ((int) $rotate + (int) $revoke + (int) ($grant !== null) > 1) {
            $this->error('pass one of --rotate, --revoke or --grant');

            return self::FAILURE;
        }
        if (! $rotate && ! $revoke && $grant === null) {
            return $this->create($container, $clientId);
        }
        if ($this->stringOption('owner') !== null || $this->option('no-owner') === true || $this->stringOption('abilities') !== null) {
            $this->error('--owner, --no-owner and --abilities only apply when creating a client');

            return self::FAILURE;
        }

        $client = OauthClient::query()->where('client_id', $clientId)->first();
        if ($client === null) {
            $this->error("no client \"{$clientId}\"");

            return self::FAILURE;
        }

        if ($grant !== null) {
            return $this->grant($client, $grant);
        }

        if ($revoke) {
            $client->revoke();
            $this->info("revoked \"{$clientId}\"; its live tokens are gone");

            return self::SUCCESS;
        }

        try {
            $secret = $client->rotateSecret();
        } catch (LogicException $e) {
            $this->error($e->getMessage().'; create a new one instead');

            return self::FAILURE;
        }
        $this->printSecret($clientId, $secret, 'rotated');

        return self::SUCCESS;
    }

    private function create(Container $container, string $clientId): int
    {
        $owner = null;
        $reference = $this->stringOption('owner');
        $noOwner = $this->option('no-owner') === true;
        if (($reference === null) === ! $noOwner) {
            $this->error('pass one of --owner or --no-owner');

            return self::FAILURE;
        }
        if ($reference !== null) {
            $resolver = config('client-credentials.owner_resolver');
            if (! is_string($resolver) || $resolver === '') {
                $this->error('--owner needs client-credentials.owner_resolver set in the app');

                return self::FAILURE;
            }
            $instance = $container->make($resolver);
            if (! $instance instanceof OwnerResolver) {
                $this->error("{$resolver} does not implement ".OwnerResolver::class);

                return self::FAILURE;
            }
            $owner = $instance->resolveOwner($reference);
            if ($owner === null) {
                $this->error("no owner \"{$reference}\"");

                return self::FAILURE;
            }
        }

        try {
            [, $secret] = OauthClient::register($owner, $clientId, self::abilities($this->stringOption('abilities') ?? ''));
        } catch (InvalidArgumentException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->printSecret($clientId, $secret, 'created');

        return self::SUCCESS;
    }

    private function grant(OauthClient $client, string $list): int
    {
        $abilities = self::abilities($list);
        if ($abilities === []) {
            $this->error('--grant needs at least one ability');

            return self::FAILURE;
        }

        try {
            $client->grant($abilities);
        } catch (InvalidArgumentException|LogicException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("\"{$client->client_id}\" may now be granted: ".implode(', ', $client->allowed_abilities));

        return self::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private static function abilities(string $list): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $list)), fn (string $a): bool => $a !== ''));
    }

    private function stringArgument(string $name): string
    {
        $value = $this->argument($name);

        return is_string($value) ? $value : '';
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) ? $value : null;
    }

    private function printSecret(string $clientId, string $secret, string $verb): void
    {
        $this->info("{$verb} \"{$clientId}\". The secret is shown this once:");
        $this->line("secret: {$secret}");
    }
}
