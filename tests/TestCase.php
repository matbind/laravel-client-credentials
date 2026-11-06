<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials\Tests;

use Amfortas\ClientCredentials\ClientCredentialsServiceProvider;
use Amfortas\ClientCredentials\TokenController;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\Http\Middleware\CheckAbilities;
use Laravel\Sanctum\SanctumServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * An app with the package's table, Sanctum's, and an `operators` table
 * for tokens that act as someone. It serves the token endpoint at
 * /oauth/token and two routes guarded by abilities.
 */
abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    public const TOKEN_PATH = '/oauth/token';

    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, ClientCredentialsServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app->make(Repository::class);
        $config->set('app.name', 'test-app');
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/vendor/laravel/sanctum/database/migrations');
        $this->loadMigrationsFrom(dirname(__DIR__).'/database/migrations');
        Schema::create('operators', function (Blueprint $table): void {
            $table->id();
            $table->string('email')->unique();
            $table->timestamps();
        });
    }

    /**
     * @param  Router  $router
     */
    protected function defineRoutes($router): void
    {
        $router->post(self::TOKEN_PATH, TokenController::class);
        $router->middleware(['auth:sanctum', CheckAbilities::class.':reports:read'])
            ->get('/reports', fn () => 'reports');
        $router->middleware(['auth:sanctum', CheckAbilities::class.':reports:publish'])
            ->post('/reports/publish', fn () => 'published');
        $router->middleware('auth:sanctum')->get('/whoami', fn () => (string) Auth::id());
    }
}
