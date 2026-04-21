<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\console\controllers;

use craft\console\Controller;
use craft\helpers\Console;
use stimmt\craft\Mcp\services\OAuthService;
use yii\console\ExitCode;

/**
 * OAuth admin console commands for the craft-mcp plugin.
 */
class OauthController extends Controller {
    /** @var string[] */
    public array $redirectUri = [];

    public bool $public = false;

    public string $name = '';

    public function options($actionID): array {
        $options = parent::options($actionID);
        if ($actionID === 'register-client') {
            $options[] = 'name';
            $options[] = 'redirectUri';
            $options[] = 'public';
        }
        return $options;
    }

    public function optionAliases(): array {
        return array_merge(parent::optionAliases(), [
            'n' => 'name',
            'r' => 'redirectUri',
            'p' => 'public',
        ]);
    }

    /**
     * Register a new OAuth client (DCR-less fallback).
     *
     * Usage: craft mcp/oauth/register-client --name="My Client" --redirect-uri=http://localhost:8765/cb [--public]
     */
    public function actionRegisterClient(): int {
        if ($this->name === '') {
            $this->stderr("--name is required\n", Console::FG_RED);
            return ExitCode::USAGE;
        }

        $redirectUris = is_array($this->redirectUri) ? $this->redirectUri : [$this->redirectUri];
        $redirectUris = array_filter(array_map('strval', $redirectUris));
        if ($redirectUris === []) {
            $this->stderr("--redirect-uri is required\n", Console::FG_RED);
            return ExitCode::USAGE;
        }

        $metadata = [
            'client_name' => $this->name,
            'redirect_uris' => array_values($redirectUris),
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => $this->public ? 'none' : 'client_secret_basic',
        ];

        try {
            $result = (new OAuthService())->registerClient($metadata);
        } catch (\Throwable $e) {
            $this->stderr("Registration failed: {$e->getMessage()}\n", Console::FG_RED);
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("Client registered.\n", Console::FG_GREEN);
        $this->stdout("  client_id:     " . $result['client_id'] . "\n");
        if (isset($result['client_secret'])) {
            $this->stdout("  client_secret: " . $result['client_secret'] . "  (shown once, store securely)\n", Console::FG_YELLOW);
        }

        return ExitCode::OK;
    }

    /**
     * Regenerate the OAuth signing keypair. Invalidates all existing access tokens.
     */
    public function actionRegenerateKeys(): int {
        if (!$this->confirm('This will invalidate every active OAuth access token. Continue?', false)) {
            $this->stdout("Aborted.\n");
            return ExitCode::OK;
        }

        (new OAuthService())->regenerateKeys();
        $this->stdout("Keypair regenerated.\n", Console::FG_GREEN);

        return ExitCode::OK;
    }
}
