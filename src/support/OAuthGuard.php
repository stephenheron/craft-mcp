<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\support;

use Craft;
use craft\elements\User;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\services\OAuthService;

/**
 * Validates OAuth 2.1 bearer tokens for the MCP HTTP transport endpoint
 * and resolves the token back to a Craft user.
 */
final class OAuthGuard {
    /**
     * Authenticate the current request.
     *
     * @return User|null Null when OAuth is disabled (caller retains prior behaviour).
     * @throws OAuthGuardException On any validation failure.
     */
    public static function authorize(): ?User {
        $settings = Mcp::settings();
        if (!$settings->oauthEnabled) {
            return null;
        }

        $request = Craft::$app->getRequest();
        $authHeader = $request->getHeaders()->get('Authorization');

        if ($authHeader === null || !preg_match('/^Bearer\s+\S+/i', $authHeader)) {
            throw self::challenge('missing_token');
        }

        $psrRequest = ServerRequest::fromGlobals()
            ->withHeader('Authorization', $authHeader);

        try {
            $service = new OAuthService();
            $resourceServer = $service->getResourceServer();
            $validated = $resourceServer->validateAuthenticatedRequest($psrRequest);
        } catch (OAuthServerException $e) {
            Craft::warning('MCP OAuth token validation failed: ' . $e->getMessage(), __METHOD__);
            throw self::challenge('invalid_token');
        }

        $userId = $validated->getAttribute('oauth_user_id');
        if ($userId === null) {
            throw self::challenge('invalid_token');
        }

        $user = Craft::$app->getUsers()->getUserById((int) $userId);
        if ($user === null || $user->getStatus() !== User::STATUS_ACTIVE) {
            throw self::challenge('invalid_token');
        }

        // v1 policy: only admins can drive MCP. Re-checked on every request
        // so demoting a user invalidates their live tokens immediately.
        if (!$user->admin) {
            throw self::challenge('invalid_token');
        }

        return $user;
    }

    private static function challenge(string $error): OAuthGuardException {
        $metadataUrl = Craft::$app->getRequest()->getHostInfo() . '/.well-known/oauth-protected-resource';
        $header = sprintf(
            'Bearer realm="mcp", resource_metadata="%s"%s',
            $metadataUrl,
            $error === 'missing_token' ? '' : ', error="' . $error . '"',
        );

        return new OAuthGuardException(
            status: 401,
            wwwAuthenticate: $header,
            body: json_encode(['error' => $error]),
        );
    }
}
