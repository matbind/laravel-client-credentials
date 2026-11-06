<?php

declare(strict_types=1);

return [

    /*
     * A class implementing Amfortas\ClientCredentials\OwnerResolver, which
     * turns `oauth:client --owner=<reference>` into the model the client's
     * tokens act as. Null: no client can be given an owner, so each is
     * created with --no-owner and holds its tokens itself.
     */
    'owner_resolver' => null,

];
