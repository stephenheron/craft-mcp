<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\migrations;

use craft\db\Migration;

/**
 * Install migration for the craft-mcp plugin.
 *
 * Creates the OAuth 2.1 tables required by the HTTP transport's
 * authorization server.
 */
class Install extends Migration {
    public function safeUp(): bool {
        $this->createOAuthTables();

        return true;
    }

    public function safeDown(): bool {
        $this->dropOAuthTables();

        return true;
    }

    /**
     * Create OAuth tables, skipping any that already exist.
     *
     * Idempotent so the upgrade migration can delegate here without
     * tripping over tables created by a fresh install.
     */
    public function createOAuthTables(): void {
        if ($this->db->getTableSchema('{{%mcp_oauth_clients}}') === null) {
            $this->createClientsTable();
        }
        if ($this->db->getTableSchema('{{%mcp_oauth_auth_codes}}') === null) {
            $this->createAuthCodesTable();
        }
        if ($this->db->getTableSchema('{{%mcp_oauth_access_tokens}}') === null) {
            $this->createAccessTokensTable();
        }
        if ($this->db->getTableSchema('{{%mcp_oauth_refresh_tokens}}') === null) {
            $this->createRefreshTokensTable();
        }
        if ($this->db->getTableSchema('{{%mcp_oauth_keys}}') === null) {
            $this->createKeysTable();
        }
    }

    private function createClientsTable(): void {
        $this->createTable('{{%mcp_oauth_clients}}', [
            'client_id' => $this->string(64)->notNull(),
            'client_secret_hash' => $this->string(255)->null(),
            'client_name' => $this->string(255)->notNull(),
            'redirect_uris' => $this->text()->notNull(),
            'grant_types' => $this->text()->notNull(),
            'is_confidential' => $this->boolean()->notNull()->defaultValue(true),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
            'PRIMARY KEY([[client_id]])',
        ]);
    }

    private function createAuthCodesTable(): void {
        $this->createTable('{{%mcp_oauth_auth_codes}}', [
            'id' => $this->string(80)->notNull(),
            'client_id' => $this->string(64)->notNull(),
            'userId' => $this->integer()->notNull(),
            'scopes' => $this->text(),
            'revoked' => $this->boolean()->notNull()->defaultValue(false),
            'expires_at' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'PRIMARY KEY([[id]])',
        ]);
        $this->createIndex(null, '{{%mcp_oauth_auth_codes}}', ['expires_at']);
        $this->addForeignKey(null, '{{%mcp_oauth_auth_codes}}', ['client_id'], '{{%mcp_oauth_clients}}', ['client_id'], 'CASCADE');
        $this->addForeignKey(null, '{{%mcp_oauth_auth_codes}}', ['userId'], '{{%users}}', ['id'], 'CASCADE');
    }

    private function createAccessTokensTable(): void {
        $this->createTable('{{%mcp_oauth_access_tokens}}', [
            'id' => $this->string(80)->notNull(),
            'client_id' => $this->string(64)->notNull(),
            'userId' => $this->integer()->notNull(),
            'scopes' => $this->text(),
            'revoked' => $this->boolean()->notNull()->defaultValue(false),
            'expires_at' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'PRIMARY KEY([[id]])',
        ]);
        $this->createIndex(null, '{{%mcp_oauth_access_tokens}}', ['userId']);
        $this->createIndex(null, '{{%mcp_oauth_access_tokens}}', ['expires_at']);
        $this->addForeignKey(null, '{{%mcp_oauth_access_tokens}}', ['client_id'], '{{%mcp_oauth_clients}}', ['client_id'], 'CASCADE');
        $this->addForeignKey(null, '{{%mcp_oauth_access_tokens}}', ['userId'], '{{%users}}', ['id'], 'CASCADE');
    }

    private function createRefreshTokensTable(): void {
        $this->createTable('{{%mcp_oauth_refresh_tokens}}', [
            'id' => $this->string(80)->notNull(),
            'access_token_id' => $this->string(80)->notNull(),
            'revoked' => $this->boolean()->notNull()->defaultValue(false),
            'expires_at' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'PRIMARY KEY([[id]])',
        ]);
        $this->createIndex(null, '{{%mcp_oauth_refresh_tokens}}', ['expires_at']);
    }

    private function createKeysTable(): void {
        // Single-row table, id pinned to 1. private_key and encryption_key
        // are stored encrypted at rest under Craft's security key;
        // public_key is plain PEM.
        $this->createTable('{{%mcp_oauth_keys}}', [
            'id' => $this->tinyInteger()->notNull(),
            'private_key' => $this->text()->notNull(),
            'public_key' => $this->text()->notNull(),
            'encryption_key' => $this->text()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'PRIMARY KEY([[id]])',
        ]);
    }

    public function dropOAuthTables(): void {
        $this->dropTableIfExists('{{%mcp_oauth_keys}}');
        $this->dropTableIfExists('{{%mcp_oauth_refresh_tokens}}');
        $this->dropTableIfExists('{{%mcp_oauth_access_tokens}}');
        $this->dropTableIfExists('{{%mcp_oauth_auth_codes}}');
        $this->dropTableIfExists('{{%mcp_oauth_clients}}');
    }
}
