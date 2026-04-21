<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\repositories;

use Craft;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use stimmt\craft\Mcp\oauth\entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface {
    public function getClientEntity($clientIdentifier): ?ClientEntityInterface {
        $row = (new \craft\db\Query())
            ->from('{{%mcp_oauth_clients}}')
            ->where(['client_id' => $clientIdentifier])
            ->one();

        if ($row === null) {
            return null;
        }

        $entity = new ClientEntity();
        $entity->setIdentifier($row['client_id']);
        $entity->setName($row['client_name']);
        $redirectUris = json_decode($row['redirect_uris'], true) ?: [];
        $entity->setRedirectUri(count($redirectUris) === 1 ? $redirectUris[0] : $redirectUris);
        $entity->setConfidential((bool) $row['is_confidential']);

        return $entity;
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool {
        $row = (new \craft\db\Query())
            ->select(['client_secret_hash', 'is_confidential', 'grant_types'])
            ->from('{{%mcp_oauth_clients}}')
            ->where(['client_id' => $clientIdentifier])
            ->one();

        if ($row === null) {
            return false;
        }

        if ($grantType !== null) {
            $grants = json_decode($row['grant_types'], true) ?: [];
            if (!in_array($grantType, $grants, true)) {
                return false;
            }
        }

        if (!$row['is_confidential']) {
            return true;
        }

        if ($clientSecret === null || $clientSecret === '') {
            return false;
        }

        return password_verify($clientSecret, $row['client_secret_hash']);
    }
}
