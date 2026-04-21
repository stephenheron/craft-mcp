<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\controllers;

use Craft;
use craft\web\Controller;
use stimmt\craft\Mcp\Mcp;
use yii\web\Response;

class OauthMetadataController extends Controller {
    protected array|bool|int $allowAnonymous = true;

    public $enableCsrfValidation = false;

    public function actionProtectedResource(): Response {
        $base = Craft::$app->getRequest()->getHostInfo();

        return $this->asJson([
            'resource' => $base . '/mcp',
            'authorization_servers' => [$base],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => Mcp::settings()->oauthScopesSupported,
            'resource_documentation' => 'https://github.com/stimmtdigital/craft-mcp',
        ]);
    }

    public function actionAuthorizationServer(): Response {
        $base = Craft::$app->getRequest()->getHostInfo();
        $settings = Mcp::settings();

        $metadata = [
            'issuer' => $base,
            'authorization_endpoint' => $base . '/mcp/oauth/authorize',
            'token_endpoint' => $base . '/mcp/oauth/token',
            'revocation_endpoint' => $base . '/mcp/oauth/revoke',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'scopes_supported' => $settings->oauthScopesSupported,
        ];

        if ($settings->oauthAllowDcr) {
            $metadata['registration_endpoint'] = $base . '/mcp/oauth/register';
        }

        return $this->asJson($metadata);
    }
}
