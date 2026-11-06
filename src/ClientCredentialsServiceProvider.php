<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Support\ServiceProvider;

/**
 * Registers `oauth:client` and the config. The app publishes the
 * migration and the config, and routes [TokenController] itself:
 *
 *   php artisan vendor:publish --tag=client-credentials-migrations
 *   php artisan vendor:publish --tag=client-credentials-config
 */
final class ClientCredentialsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(dirname(__DIR__).'/config/client-credentials.php', 'client-credentials');
    }

    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([ManageOauthClient::class]);
        $this->publishes([
            dirname(__DIR__).'/config/client-credentials.php' => config_path('client-credentials.php'),
        ], 'client-credentials-config');
        // Dated in its own name, so it runs in order whether or not the app
        // has publishing set to re-date migrations.
        $this->publishesMigrations([
            dirname(__DIR__).'/database/migrations' => database_path('migrations'),
        ], 'client-credentials-migrations');
    }
}
