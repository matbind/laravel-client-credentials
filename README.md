# laravel-client-credentials

The OAuth 2.0 client-credentials grant ([RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)) for Laravel. A machine holds a client id and secret instead of a long-lived token, and trades them for a [Sanctum](https://laravel.com/docs/sanctum) token that expires after an hour and carries only the abilities its client row allows. Sanctum's `auth:sanctum` and `abilities:` middleware then treat it like any other token.

- Secrets are stored as argon2id hashes and shown once.
- The endpoint is rate-limited per address; an unknown id takes as long to refuse as a wrong secret, and no one can lock a client out.
- Refusals are answered, never logged, so no secret reaches a log through a stack trace.
- A client's abilities are written down in one place, its row. An empty `scope` asks for all of them, a non-empty one for a subset.
- Rotating or revoking a client kills the tokens it has already minted.

Requires PHP 8.2, Laravel 11 or 12, and Sanctum 4.

## Install

```sh
composer require amfortas/laravel-client-credentials
php artisan vendor:publish --tag=client-credentials-migrations
php artisan migrate
```

Route the token endpoint wherever the app wants it. `TokenController::route` puts it behind the package's limiter, 60 requests a minute per address: each request costs an argon2id hash, known client id or not.

```php
use Amfortas\ClientCredentials\TokenController;

TokenController::route('oauth/token');
```

Behind a reverse proxy, configure Laravel's trusted proxies so `$request->ip()` is the caller and not the proxy; otherwise every caller shares one limit. An app can redefine the limiter after the package boots: `RateLimiter::for(TokenController::LIMITER, ...)`.

Guard routes by ability as with any Sanctum token:

```php
Route::middleware(['auth:sanctum', 'abilities:reports:read'])->get('reports', ...);
```

Routes that take these tokens without `auth:sanctum` ask the package what a presented token holds, and get null for anything but a live token a client was issued:

```php
$abilities = OauthClient::abilitiesOfToken($request->bearerToken() ?? '');
```

## Clients

```sh
php artisan oauth:client broker --no-owner --abilities=reports:read,reports:write
php artisan oauth:client broker --grant=reports:publish
php artisan oauth:client broker --rotate
php artisan oauth:client broker --revoke
```

Creating says who the tokens act as, `--owner=…` or `--no-owner` (below); leaving both out is refused. Creating and rotating print the secret once. The wildcard ability `*` is refused.

## Requesting a token

```sh
curl -X POST https://app.example/oauth/token \
  -u "broker:$SECRET" \
  -d grant_type=client_credentials \
  -d scope="reports:read"
```

```json
{"access_token": "…", "token_type": "Bearer", "expires_in": 3600, "scope": "reports:read"}
```

Credentials come as HTTP Basic or in the form body, never both and never in the query string. Errors follow RFC 6749 §5.2.

## Who a token acts as

A client created with `--no-owner` holds its tokens itself, and `auth:sanctum` then returns the `OauthClient` as the user: it is Authenticatable, with ids of its own, so an app that also has users must tell the two apart by class before it reads `->id`. To have the tokens act as one of the app's models instead (a user, say), publish the config and name a resolver:

```sh
php artisan vendor:publish --tag=client-credentials-config
```

```php
// config/client-credentials.php
'owner_resolver' => App\Auth\UsersByEmail::class,
```

```php
use Amfortas\ClientCredentials\OwnerResolver;

final class UsersByEmail implements OwnerResolver
{
    public function resolveOwner(string $reference): ?User
    {
        return User::query()->where('email', $reference)->first();
    }
}
```

```sh
php artisan oauth:client broker --owner=ops@example.com --abilities=reports:read
```

The owner must implement Sanctum's `HasApiTokens` contract. A client whose owner is deleted gets no more tokens.

An app that enforces a morph map must name `Amfortas\ClientCredentials\OauthClient` in it, and the owner's class.

Issuing a token removes the client's expired ones, so they do not pile up even where nothing runs `sanctum:prune-expired`.

## Development

```sh
composer install
composer check   # pint, phpstan at max level, phpunit
```

## Licence

MIT
