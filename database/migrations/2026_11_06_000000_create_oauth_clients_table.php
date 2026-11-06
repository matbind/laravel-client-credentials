<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_clients', function (Blueprint $table): void {
            // A machine that mints its own short-lived tokens through the
            // client-credentials endpoint instead of holding a long-lived one.
            $table->id();

            $table->string('client_id')->unique();

            // argon2id. The plain secret is printed once by
            // `artisan oauth:client` and never stored.
            $table->string('secret_hash');

            // Who the issued tokens act as; none, and they belong to the
            // client itself.
            $table->nullableMorphs('owner');

            // The only place this client's abilities are written down:
            // an empty requested scope gets all of them.
            $table->json('allowed_abilities');

            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_clients');
    }
};
