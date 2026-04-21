<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\oauth\entities\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface {
    public function getScopeEntityByIdentifier($identifier): ?ScopeEntityInterface {
        if (!in_array($identifier, Mcp::settings()->oauthScopesSupported, true)) {
            return null;
        }

        $entity = new ScopeEntity();
        $entity->setIdentifier($identifier);

        return $entity;
    }

    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null,
    ): array {
        return $scopes;
    }
}
