<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\services;

use Craft;
use DateInterval;
use Defuse\Crypto\Key;
use InvalidArgumentException;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\oauth\repositories\AccessTokenRepository;
use stimmt\craft\Mcp\oauth\repositories\AuthCodeRepository;
use stimmt\craft\Mcp\oauth\repositories\ClientRepository;
use stimmt\craft\Mcp\oauth\repositories\RefreshTokenRepository;
use stimmt\craft\Mcp\oauth\repositories\ScopeRepository;

/**
 * OAuth 2.1 composition root.
 *
 * Wires league/oauth2-server with Craft-backed repositories. Signing
 * keys and the refresh-token encryption key live in `mcp_oauth_keys`
 * so they survive deploys; private and encryption keys are encrypted
 * at rest under Craft's security key.
 */
class OAuthService {
    private const KEYS_TABLE = '{{%mcp_oauth_keys}}';
    private const KEYS_ROW_ID = 1;

    /** @var array{private: string, public: string, encryption: string}|null */
    private ?array $keys = null;

    /**
     * Ensure keys exist in the DB, lazily generating on first access.
     *
     * @return array{private: string, public: string, encryption: string}
     */
    public function ensureKeys(): array {
        if ($this->keys !== null) {
            return $this->keys;
        }

        $row = $this->loadRow();
        if ($row !== null) {
            return $this->keys = $this->decodeRow($row);
        }

        $keys = $this->generateKeys();
        $this->persistRow($keys);

        return $this->keys = $keys;
    }

    public function getAuthorizationServer(): AuthorizationServer {
        $keys = $this->ensureKeys();

        $settings = Mcp::settings();
        $privateKey = new CryptKey($keys['private'], null, false);

        $server = new AuthorizationServer(
            new ClientRepository(),
            new AccessTokenRepository(),
            new ScopeRepository(),
            $privateKey,
            $this->encryptionKey(),
        );

        $authCodeGrant = new AuthCodeGrant(
            new AuthCodeRepository(),
            new RefreshTokenRepository(),
            new DateInterval('PT' . $settings->oauthAuthCodeTtl . 'S'),
        );
        $authCodeGrant->setRefreshTokenTTL(new DateInterval('PT' . $settings->oauthRefreshTokenTtl . 'S'));
        $server->enableGrantType($authCodeGrant, new DateInterval('PT' . $settings->oauthAccessTokenTtl . 'S'));

        $refreshGrant = new RefreshTokenGrant(new RefreshTokenRepository());
        $refreshGrant->setRefreshTokenTTL(new DateInterval('PT' . $settings->oauthRefreshTokenTtl . 'S'));
        $server->enableGrantType($refreshGrant, new DateInterval('PT' . $settings->oauthAccessTokenTtl . 'S'));

        return $server;
    }

    public function getResourceServer(): ResourceServer {
        $keys = $this->ensureKeys();

        return new ResourceServer(
            new AccessTokenRepository(),
            new CryptKey($keys['public'], null, false),
        );
    }

    /**
     * Register a new OAuth client via RFC 7591 Dynamic Client Registration.
     *
     * @param array<string, mixed> $metadata
     * @return array<string, mixed> The registration response (includes client_secret if confidential).
     */
    public function registerClient(array $metadata): array {
        $name = (string) ($metadata['client_name'] ?? 'Unnamed MCP Client');
        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === []) {
            throw new InvalidArgumentException('redirect_uris is required and must be a non-empty array');
        }
        foreach ($redirectUris as $uri) {
            if (!is_string($uri) || !filter_var($uri, FILTER_VALIDATE_URL)) {
                throw new InvalidArgumentException('redirect_uris must contain valid URLs');
            }
        }

        $grantTypes = $metadata['grant_types'] ?? ['authorization_code', 'refresh_token'];
        $allowedGrants = ['authorization_code', 'refresh_token'];
        foreach ($grantTypes as $gt) {
            if (!in_array($gt, $allowedGrants, true)) {
                throw new InvalidArgumentException("Unsupported grant type: {$gt}");
            }
        }

        $responseTypes = $metadata['response_types'] ?? ['code'];
        foreach ($responseTypes as $rt) {
            if ($rt !== 'code') {
                throw new InvalidArgumentException("Unsupported response type: {$rt}");
            }
        }

        $authMethod = $metadata['token_endpoint_auth_method'] ?? 'client_secret_basic';
        $isConfidential = $authMethod !== 'none';

        $clientId = bin2hex(random_bytes(16));
        $clientSecret = null;
        $clientSecretHash = null;
        if ($isConfidential) {
            $clientSecret = bin2hex(random_bytes(32));
            $clientSecretHash = password_hash($clientSecret, PASSWORD_DEFAULT);
        }

        $now = gmdate('Y-m-d H:i:s');
        Craft::$app->getDb()->createCommand()
            ->insert('{{%mcp_oauth_clients}}', [
                'client_id' => $clientId,
                'client_secret_hash' => $clientSecretHash,
                'client_name' => $name,
                'redirect_uris' => json_encode(array_values($redirectUris)),
                'grant_types' => json_encode(array_values($grantTypes)),
                'is_confidential' => $isConfidential,
                'dateCreated' => $now,
                'dateUpdated' => $now,
                'uid' => \craft\helpers\StringHelper::UUID(),
            ])
            ->execute();

        $response = [
            'client_id' => $clientId,
            'client_name' => $name,
            'redirect_uris' => array_values($redirectUris),
            'grant_types' => array_values($grantTypes),
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $isConfidential ? $authMethod : 'none',
        ];
        if ($clientSecret !== null) {
            $response['client_secret'] = $clientSecret;
        }

        return $response;
    }

    public function deleteClient(string $clientId): void {
        Craft::$app->getDb()->createCommand()
            ->delete('{{%mcp_oauth_clients}}', ['client_id' => $clientId])
            ->execute();
    }

    public function encryptionKey(): string {
        $settings = Mcp::settings();
        if (is_string($settings->oauthEncryptionKey) && $settings->oauthEncryptionKey !== '') {
            return $settings->oauthEncryptionKey;
        }

        return $this->ensureKeys()['encryption'];
    }

    /**
     * Drop the stored keys and regenerate. Invalidates every live access
     * and refresh token because token signatures / payload encryption
     * no longer verify against the new material.
     */
    public function regenerateKeys(): void {
        Craft::$app->getDb()->createCommand()
            ->delete(self::KEYS_TABLE, ['id' => self::KEYS_ROW_ID])
            ->execute();
        $this->keys = null;
        $this->ensureKeys();
    }

    /**
     * @return array{private_key: string, public_key: string, encryption_key: string}|null
     */
    private function loadRow(): ?array {
        $row = (new \craft\db\Query())
            ->select(['private_key', 'public_key', 'encryption_key'])
            ->from(self::KEYS_TABLE)
            ->where(['id' => self::KEYS_ROW_ID])
            ->one();

        return $row ?: null;
    }

    /**
     * @param array{private_key: string, public_key: string, encryption_key: string} $row
     * @return array{private: string, public: string, encryption: string}
     */
    private function decodeRow(array $row): array {
        $security = Craft::$app->getSecurity();
        $private = $security->decryptByKey(base64_decode($row['private_key']));
        $encryption = $security->decryptByKey(base64_decode($row['encryption_key']));
        if ($private === false || $encryption === false) {
            throw new \RuntimeException('Failed to decrypt OAuth keys — has CRAFT_SECURITY_KEY changed?');
        }

        return [
            'private' => $private,
            'public' => $row['public_key'],
            'encryption' => $encryption,
        ];
    }

    /**
     * @param array{private: string, public: string, encryption: string} $keys
     */
    private function persistRow(array $keys): void {
        $security = Craft::$app->getSecurity();
        $now = gmdate('Y-m-d H:i:s');

        Craft::$app->getDb()->createCommand()
            ->upsert(self::KEYS_TABLE, [
                'id' => self::KEYS_ROW_ID,
                'private_key' => base64_encode($security->encryptByKey($keys['private'])),
                'public_key' => $keys['public'],
                'encryption_key' => base64_encode($security->encryptByKey($keys['encryption'])),
                'dateCreated' => $now,
                'dateUpdated' => $now,
            ], [
                'private_key' => base64_encode($security->encryptByKey($keys['private'])),
                'public_key' => $keys['public'],
                'encryption_key' => base64_encode($security->encryptByKey($keys['encryption'])),
                'dateUpdated' => $now,
            ])
            ->execute();
    }

    /**
     * @return array{private: string, public: string, encryption: string}
     */
    private function generateKeys(): array {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($resource === false) {
            throw new \RuntimeException('Failed to generate OAuth keypair: ' . openssl_error_string());
        }
        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        $publicKey = $details['key'] ?? null;
        if ($publicKey === null) {
            throw new \RuntimeException('Failed to extract public key from generated keypair');
        }

        return [
            'private' => $privateKey,
            'public' => $publicKey,
            'encryption' => Key::createNewRandomKey()->saveToAsciiSafeString(),
        ];
    }
}
