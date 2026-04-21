<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\migrations;

use craft\db\Migration;

/**
 * Adds OAuth 2.1 tables to existing craft-mcp installs that predate
 * schemaVersion 1.1.0. No-op on fresh installs because Install.php
 * creates the tables first and createOAuthTables() checks for existence.
 */
class m260421_000000_oauth_tables extends Migration {
    public function safeUp(): bool {
        (new Install())->createOAuthTables();

        return true;
    }

    public function safeDown(): bool {
        (new Install())->dropOAuthTables();

        return true;
    }
}
