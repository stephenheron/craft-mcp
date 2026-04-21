<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\repositories;

use Craft;
use DateTimeZone;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use stimmt\craft\Mcp\oauth\entities\AccessTokenEntity;
use yii\db\Exception as DbException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;

class AccessTokenRepository implements AccessTokenRepositoryInterface {
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): AccessTokenEntityInterface {
        $entity = new AccessTokenEntity();
        $entity->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $entity->addScope($scope);
        }
        $entity->setUserIdentifier($userIdentifier);

        return $entity;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void {
        $expires = $accessTokenEntity->getExpiryDateTime()
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d H:i:s');

        try {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%mcp_oauth_access_tokens}}', [
                    'id' => $accessTokenEntity->getIdentifier(),
                    'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
                    'userId' => (int) $accessTokenEntity->getUserIdentifier(),
                    'scopes' => json_encode(array_map(fn ($s) => $s->getIdentifier(), $accessTokenEntity->getScopes())),
                    'revoked' => false,
                    'expires_at' => $expires,
                    'dateCreated' => gmdate('Y-m-d H:i:s'),
                ])
                ->execute();
        } catch (DbException $e) {
            if ($this->isDuplicate($e)) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            throw $e;
        }
    }

    public function revokeAccessToken($tokenId): void {
        Craft::$app->getDb()->createCommand()
            ->update('{{%mcp_oauth_access_tokens}}', ['revoked' => true], ['id' => $tokenId])
            ->execute();
    }

    public function isAccessTokenRevoked($tokenId): bool {
        $row = (new \craft\db\Query())
            ->select(['revoked', 'expires_at'])
            ->from('{{%mcp_oauth_access_tokens}}')
            ->where(['id' => $tokenId])
            ->one();

        if ($row === null) {
            return true;
        }

        if ((bool) $row['revoked']) {
            return true;
        }

        return strtotime($row['expires_at'] . ' UTC') < time();
    }

    private function isDuplicate(DbException $e): bool {
        return str_contains($e->getMessage(), 'Duplicate') || str_contains($e->getMessage(), 'UNIQUE');
    }
}
