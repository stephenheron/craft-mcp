<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\models;

use craft\base\Model;
use Override;

/**
 * MCP Plugin Settings.
 *
 * A simple value object - config loading is handled by the Mcp class.
 *
 * @author Max van Essen <support@stimmt.digital>
 */
class Settings extends Model {
    public bool $enabled = true;

    /** @var string[] */
    public array $disabledTools = [];

    /** @var string[] */
    public array $disabledPrompts = [];

    /** @var string[] */
    public array $disabledResources = [];

    public bool $enableDangerousTools = true;

    public bool $enableHttpTransport = false;

    /** @var string[] */
    public array $allowedIps = [];

    public bool $oauthEnabled = false;

    public int $oauthAccessTokenTtl = 3600;

    public int $oauthRefreshTokenTtl = 2592000;

    public int $oauthAuthCodeTtl = 600;

    public bool $oauthAllowDcr = true;

    public bool $oauthRequireConsent = true;

    /** @var string[] */
    public array $oauthScopesSupported = ['mcp:tools'];

    public ?string $oauthEncryptionKey = null;

    /**
     * @return array<int, array<int|string, mixed>>
     */
    #[Override]
    public function defineRules(): array {
        return [
            [['enabled', 'enableDangerousTools', 'enableHttpTransport', 'oauthEnabled', 'oauthAllowDcr', 'oauthRequireConsent'], 'boolean'],
            [['disabledTools', 'disabledPrompts', 'disabledResources', 'allowedIps', 'oauthScopesSupported'], 'each', 'rule' => ['string']],
            [['oauthAccessTokenTtl', 'oauthRefreshTokenTtl', 'oauthAuthCodeTtl'], 'integer', 'min' => 1],
            ['oauthEncryptionKey', 'string'],
        ];
    }
}
