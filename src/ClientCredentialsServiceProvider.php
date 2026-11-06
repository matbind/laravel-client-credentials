<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

/**
 * Registers `oauth:client`, the config and the endpoint's rate limiter.
 * The app publishes the migration and the config, and routes
 * [TokenController] itself with `TokenController::route('oauth/token')`:
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
        RateLimiter::for(
            TokenController::LIMITER,
            fn (Request $request): Limit => Limit::perMinute(TokenController::REQUESTS_PER_MINUTE)->by((string) $request->ip()),
        );

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
