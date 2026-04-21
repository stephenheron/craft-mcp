<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\repositories;

use Craft;
use DateTimeZone;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use stimmt\craft\Mcp\oauth\entities\AuthCodeEntity;
use yii\db\Exception as DbException;

class AuthCodeRepository implements AuthCodeRepositoryInterface {
    public function getNewAuthCode(): AuthCodeEntityInterface {
        return new AuthCodeEntity();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void {
        $expires = $authCodeEntity->getExpiryDateTime()
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d H:i:s');

        try {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%mcp_oauth_auth_codes}}', [
                    'id' => $authCodeEntity->getIdentifier(),
                    'client_id' => $authCodeEntity->getClient()->getIdentifier(),
                    'userId' => (int) $authCodeEntity->getUserIdentifier(),
                    'scopes' => json_encode(array_map(fn ($s) => $s->getIdentifier(), $authCodeEntity->getScopes())),
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

    public function revokeAuthCode($codeId): void {
        Craft::$app->getDb()->createCommand()
            ->update('{{%mcp_oauth_auth_codes}}', ['revoked' => true], ['id' => $codeId])
            ->execute();
    }

    public function isAuthCodeRevoked($codeId): bool {
        $row = (new \craft\db\Query())
            ->select(['revoked', 'expires_at'])
            ->from('{{%mcp_oauth_auth_codes}}')
            ->where(['id' => $codeId])
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
