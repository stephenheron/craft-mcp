<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\repositories;

use Craft;
use DateTimeZone;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use stimmt\craft\Mcp\oauth\entities\RefreshTokenEntity;
use yii\db\Exception as DbException;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface {
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface {
        return new RefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void {
        $expires = $refreshTokenEntity->getExpiryDateTime()
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d H:i:s');

        try {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%mcp_oauth_refresh_tokens}}', [
                    'id' => $refreshTokenEntity->getIdentifier(),
                    'access_token_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
                    'revoked' => false,
                    'expires_at' => $expires,
                    'dateCreated' => gmdate('Y-m-d H:i:s'),
                ])
                ->execute();
        } catch (DbException $e) {
            if (str_contains($e->getMessage(), 'Duplicate') || str_contains($e->getMessage(), 'UNIQUE')) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            throw $e;
        }
    }

    public function revokeRefreshToken($tokenId): void {
        Craft::$app->getDb()->createCommand()
            ->update('{{%mcp_oauth_refresh_tokens}}', ['revoked' => true], ['id' => $tokenId])
            ->execute();
    }

    public function isRefreshTokenRevoked($tokenId): bool {
        $row = (new \craft\db\Query())
            ->select(['revoked', 'expires_at'])
            ->from('{{%mcp_oauth_refresh_tokens}}')
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
}
