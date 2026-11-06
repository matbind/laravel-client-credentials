<?php

declare(strict_types=1);

namespace Amfortas\ClientCredentials;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Authenticatable as AuthenticatesAsItself;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Hashing\Argon2IdHasher;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Sanctum\Contracts\HasApiTokens as HoldsTokens;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\NewAccessToken;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;
use LogicException;
use SensitiveParameter;

/**
 * A machine allowed to mint its own tokens through the client-credentials
 * endpoint (see [ClientCredentialsGrant]). It holds a secret instead of a
 * token, and every token it gets back expires within the hour, so a leaked
 * token is short-lived and a leaked secret is one `--rotate` away from
 * useless.
 *
 * The tokens it issues are ordinary Sanctum tokens named
 * `oauth:<client_id>`, held by its owner, or by the client itself when it
 * was registered without one; that name is how rotating or revoking the
 * client finds and kills the ones still live. Only this class knows it.
 * A client holding its own tokens is what `auth:sanctum` then returns as
 * the user, so it is Authenticatable, with its own id; an app with users
 * of its own tells the two apart by class.
 *
 * Every save checks the abilities: at least one, and never `*`, which
 * would make its tokens as strong as any the app has. That holds however
 * the row is written, not only through `artisan oauth:client`.
 *
 * @property int $id
 * @property string $client_id
 * @property string $secret_hash argon2id
 * @property string|null $owner_type
 * @property int|string|null $owner_id
 * @property-read (Model&HoldsTokens)|null $owner
 * @property list<string> $allowed_abilities
 * @property CarbonImmutable|null $revoked_at
 */
class OauthClient extends Model implements Authenticatable, HoldsTokens
{
    use AuthenticatesAsItself;
    use HasApiTokens;

    /**
     * Where the hash an unknown client_id is checked against is kept. Made
     * once by the same hasher with the same costs as real secrets, so an
     * unknown id takes as long to refuse as a wrong secret.
     */
    private const DUMMY_HASH_KEY = 'client-credentials:dummy-hash';

    /** How long a token this server issues lives. */
    public const TOKEN_LIFETIME_SECONDS = 3600;

    protected $table = 'oauth_clients';

    protected $fillable = [
        'client_id',
        'allowed_abilities',
    ];

    protected $hidden = [
        'secret_hash',
    ];

    protected function casts(): array
    {
        return [
            'allowed_abilities' => 'array',
            'revoked_at' => 'immutable_datetime',
        ];
    }

    protected static function booted(): void
    {
        static::saving(function (OauthClient $client): void {
            $abilities = $client->allowed_abilities;
            if ($abilities === []) {
                throw new InvalidArgumentException('a client needs at least one ability');
            }
            if (in_array('*', $abilities, true)) {
                throw new InvalidArgumentException('the wildcard ability is not allowed');
            }
        });
    }

    /**
     * Create a client and return it with its secret in plain text. The
     * secret is not stored, so the caller shows it once and forgets it.
     * Either the whole client is saved or none of it.
     *
     * @param  (Model&HoldsTokens)|null  $owner  Who its tokens act as; null for the client itself.
     * @param  list<string>  $abilities
     * @return array{0: self, 1: string}
     *
     * @throws InvalidArgumentException when the id is taken or the abilities are refused
     * @throws ClassMorphViolationException when the app enforces a morph map that names neither this class nor the owner's
     */
    public static function register((Model&HoldsTokens)|null $owner, string $clientId, array $abilities): array
    {
        return DB::transaction(function () use ($owner, $clientId, $abilities): array {
            if (self::query()->where('client_id', $clientId)->exists()) {
                throw new InvalidArgumentException("client \"{$clientId}\" exists");
            }

            $client = new self([
                'client_id' => $clientId,
                'allowed_abilities' => $abilities,
            ]);
            if ($owner !== null) {
                $client->owner()->associate($owner);
            }

            return [$client, $client->rotateSecret()];
        });
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function owner(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Give the client a new secret, kill the tokens the old one minted,
     * and return the new secret in plain text.
     *
     * @throws LogicException for a revoked client, whose secret would be refused anyway
     */
    public function rotateSecret(): string
    {
        $this->refuseIfRevoked();

        $secret = Str::random(48);
        $this->secret_hash = self::hasher()->make($secret);
        $this->save();
        $this->deleteIssuedTokens();

        return $secret;
    }

    /**
     * Let the client be granted these abilities too, on top of the ones
     * it has. Its live tokens keep the abilities they were issued with;
     * the next token it mints may carry the new ones.
     *
     * @param  list<string>  $abilities
     *
     * @throws LogicException for a revoked client, which mints no more tokens
     * @throws InvalidArgumentException when the abilities are refused
     */
    public function grant(array $abilities): void
    {
        $this->refuseIfRevoked();

        $this->allowed_abilities = array_values(array_unique([...$this->allowed_abilities, ...$abilities]));
        $this->save();
    }

    /**
     * The client with exactly this id and secret that may still get
     * tokens, or null. An unknown id costs one hash check like a known
     * one, so the time taken does not tell which ids exist. A client whose
     * owner is gone gets no more tokens.
     */
    public static function authenticate(string $clientId, #[SensitiveParameter] string $secret): ?self
    {
        $client = self::query()->where('client_id', $clientId)->first();
        if ($client === null || $client->client_id !== $clientId) {
            self::hasher()->check($secret, self::dummyHash());

            return null;
        }

        if (! self::hasher()->check($secret, $client->secret_hash) || $client->isRevoked() || $client->hasLostItsOwner()) {
            return null;
        }

        return $client;
    }

    /**
     * The abilities a presented bearer token holds, when it is a live
     * token this server issued to a client that may still get tokens; null
     * for any other token, or none, or when none of its abilities is left.
     * A client's token is known by its exact name, its holder and its
     * life, which is no longer than the server gives. Only abilities the
     * client is still allowed count, so narrowing a client takes effect
     * at once and no token carries more than its client row. An app whose own
     * routes take these tokens without `auth:sanctum` asks here, so it
     * needs to know nothing of how a client marks its tokens.
     *
     * @return list<string>|null
     */
    public static function abilitiesOfToken(#[SensitiveParameter] string $presented): ?array
    {
        $token = $presented === '' ? null : Sanctum::personalAccessTokenModel()::findToken($presented);
        if (! $token instanceof PersonalAccessToken || ! str_starts_with($token->name, 'oauth:')) {
            return null;
        }
        $client = self::query()->where('client_id', substr($token->name, strlen('oauth:')))->first();
        if ($client === null || $token->name !== $client->tokenName() || $client->isRevoked() || $client->hasLostItsOwner()) {
            return null;
        }
        if (! self::isLiveIssuedToken($token)) {
            return null;
        }
        $holder = $client->tokenHolder();
        $tokenable = $token->tokenable;
        if (! $holder instanceof Model || ! $tokenable instanceof Model || ! $tokenable->is($holder)) {
            return null;
        }

        $abilities = array_values(array_intersect(array_filter($token->abilities ?? [], 'is_string'), $client->allowed_abilities));

        return $abilities === [] ? null : $abilities;
    }

    /**
     * Whether the token is still within the life this server gives a token,
     * and within Sanctum's own `sanctum.expiration` when the app sets one;
     * a token made by hand to last longer is not one this server issued.
     */
    private static function isLiveIssuedToken(PersonalAccessToken $token): bool
    {
        $created = $token->created_at;
        $expires = $token->expires_at;
        if ($created === null || $expires === null || ! $expires->isFuture()) {
            return false;
        }
        if ($expires->getTimestamp() - $created->getTimestamp() > self::TOKEN_LIFETIME_SECONDS) {
            return false;
        }
        $minutes = config('sanctum.expiration');

        return ! is_numeric($minutes) || $created->copy()->addMinutes((int) $minutes)->isFuture();
    }

    /**
     * Mint a token carrying these abilities, which must all be ones the
     * client may be granted, and drop the client's tokens that have
     * expired, so they do not pile up where nothing prunes them.
     *
     * @param  list<string>  $abilities
     *
     * @throws InvalidArgumentException for an ability the client may not be granted
     */
    public function issueToken(array $abilities, CarbonImmutable $expiresAt): NewAccessToken
    {
        if ($abilities === [] || array_diff($abilities, $this->allowed_abilities) !== []) {
            throw new InvalidArgumentException("client \"{$this->client_id}\" may not be granted these abilities");
        }

        $holder = $this->tokenHolder();
        $holder->tokens()
            ->where('name', $this->tokenName())
            ->where('expires_at', '<=', CarbonImmutable::now())
            ->delete();

        return $holder->createToken($this->tokenName(), $abilities, $expiresAt);
    }

    /**
     * Stop the client for good: no new tokens, and none of its live ones
     * keep working out their hour.
     */
    public function revoke(): void
    {
        $this->revoked_at = CarbonImmutable::now('UTC');
        $this->save();
        $this->deleteIssuedTokens();
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    private function refuseIfRevoked(): void
    {
        if ($this->isRevoked()) {
            throw new LogicException("client \"{$this->client_id}\" is revoked");
        }
    }

    private function hasLostItsOwner(): bool
    {
        return $this->owner_type !== null && ! $this->owner instanceof HoldsTokens;
    }

    private function tokenName(): string
    {
        return 'oauth:'.$this->client_id;
    }

    private function deleteIssuedTokens(): void
    {
        if ($this->hasLostItsOwner()) {
            return;
        }
        $this->tokenHolder()->tokens()->where('name', $this->tokenName())->delete();
    }

    /**
     * The owner, or the client itself when it was registered without one.
     *
     * @throws LogicException for a client whose owner is gone, which must not fall back to itself
     */
    private function tokenHolder(): HoldsTokens
    {
        if ($this->owner_type === null) {
            return $this;
        }
        $owner = $this->owner;
        if (! $owner instanceof HoldsTokens) {
            throw new LogicException("the owner of client \"{$this->client_id}\" is gone");
        }

        return $owner;
    }

    private static function dummyHash(): string
    {
        return Cache::rememberForever(self::DUMMY_HASH_KEY, fn (): string => self::hasher()->make(Str::random(48)));
    }

    private static function hasher(): Argon2IdHasher
    {
        return Hash::createArgon2idDriver();
    }
}
