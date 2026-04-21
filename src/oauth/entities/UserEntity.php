<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\entities;

use League\OAuth2\Server\Entities\UserEntityInterface;

final class UserEntity implements UserEntityInterface {
    public function __construct(private readonly int|string $identifier) {
    }

    public function getIdentifier(): string {
        return (string) $this->identifier;
    }
}
