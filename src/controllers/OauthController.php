<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\controllers;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use craft\web\Response as CraftResponse;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\oauth\entities\UserEntity;
use stimmt\craft\Mcp\services\OAuthService;
use yii\web\Response as YiiResponse;

class OauthController extends Controller {
    protected array|bool|int $allowAnonymous = true;

    public $enableCsrfValidation = false;

    public function actionAuthorize(): YiiResponse {
        $this->requireOAuthEnabled();

        $psrRequest = $this->buildPsrRequestForAuthorize();
        $service = new OAuthService();

        try {
            $authRequest = $service->getAuthorizationServer()->validateAuthorizationRequest($psrRequest);
        } catch (OAuthServerException $e) {
            return $this->emitPsrResponse($e->generateHttpResponse(new PsrResponse()));
        }

        $craftRequest = Craft::$app->getRequest();

        if ($craftRequest->getIsGet()) {
            return $this->renderConsent($authRequest, $psrRequest, null);
        }

        $username = (string) $craftRequest->getBodyParam('username', '');
        $password = (string) $craftRequest->getBodyParam('password', '');
        $approve = $craftRequest->getBodyParam('approve');

        if (Mcp::settings()->oauthRequireConsent && $approve !== '1') {
            $denied = OAuthServerException::accessDenied('The user denied the request', $authRequest->getRedirectUri());
            return $this->emitPsrResponse($denied->generateHttpResponse(new PsrResponse()));
        }

        $user = $this->findUser($username);
        if ($user === null || !$user->authenticate($password)) {
            return $this->renderConsent($authRequest, $psrRequest, 'Invalid username or password');
        }

        $authRequest->setUser(new UserEntity((int) $user->id));
        $authRequest->setAuthorizationApproved(true);

        try {
            $response = $service->getAuthorizationServer()
                ->completeAuthorizationRequest($authRequest, new PsrResponse());
        } catch (OAuthServerException $e) {
            return $this->emitPsrResponse($e->generateHttpResponse(new PsrResponse()));
        }

        return $this->emitPsrResponse($response);
    }

    public function actionToken(): YiiResponse {
        $this->requireOAuthEnabled();

        $psrRequest = ServerRequest::fromGlobals();
        $service = new OAuthService();

        try {
            $response = $service->getAuthorizationServer()
                ->respondToAccessTokenRequest($psrRequest, new PsrResponse());
        } catch (OAuthServerException $e) {
            return $this->emitPsrResponse($e->generateHttpResponse(new PsrResponse()));
        }

        return $this->emitPsrResponse($response);
    }

    public function actionRegister(): YiiResponse {
        $this->requireOAuthEnabled();

        $settings = Mcp::settings();
        if (!$settings->oauthAllowDcr) {
            return $this->asJsonResponse(['error' => 'Dynamic Client Registration is disabled'], 403);
        }

        if (!$this->checkDcrRateLimit()) {
            return $this->asJsonResponse(['error' => 'Too Many Requests'], 429);
        }

        $body = (string) Craft::$app->getRequest()->getRawBody();
        $metadata = json_decode($body, true);
        if (!is_array($metadata)) {
            return $this->asJsonResponse(['error' => 'invalid_client_metadata', 'error_description' => 'Request body must be JSON'], 400);
        }

        try {
            $response = (new OAuthService())->registerClient($metadata);
        } catch (\InvalidArgumentException $e) {
            return $this->asJsonResponse(['error' => 'invalid_client_metadata', 'error_description' => $e->getMessage()], 400);
        }

        return $this->asJsonResponse($response, 201);
    }

    public function actionRevoke(): YiiResponse {
        $this->requireOAuthEnabled();

        $token = (string) Craft::$app->getRequest()->getBodyParam('token', '');
        if ($token === '') {
            return $this->asJsonResponse([], 200);
        }

        $service = new OAuthService();

        try {
            $parser = new \Lcobucci\JWT\Token\Parser(new \Lcobucci\JWT\Encoding\JoseEncoder());
            $parsed = $parser->parse($token);
            $jti = $parsed->claims()->get('jti');
            if (is_string($jti) && $jti !== '') {
                (new \stimmt\craft\Mcp\oauth\repositories\AccessTokenRepository())->revokeAccessToken($jti);
            }
        } catch (\Throwable) {
            // Token may be a refresh token or unparseable — try refresh repo.
            try {
                $decrypted = $this->decryptRefreshPayload($token, $service->encryptionKey());
                if (is_array($decrypted) && isset($decrypted['refresh_token_id'])) {
                    (new \stimmt\craft\Mcp\oauth\repositories\RefreshTokenRepository())
                        ->revokeRefreshToken((string) $decrypted['refresh_token_id']);
                }
            } catch (\Throwable) {
                // Ignore — RFC 7009 says always return 200.
            }
        }

        return $this->asJsonResponse([], 200);
    }

    private function requireOAuthEnabled(): void {
        if (!Mcp::settings()->oauthEnabled) {
            throw new \yii\web\ForbiddenHttpException('OAuth is disabled');
        }
    }

    private function findUser(string $loginName): ?User {
        if ($loginName === '') {
            return null;
        }
        return User::find()
            ->username($loginName)
            ->addSelect(['users.password', 'users.passwordResetRequired', 'users.locked', 'users.suspended', 'users.pending', 'users.active'])
            ->one() ?? User::find()
                ->email($loginName)
                ->addSelect(['users.password', 'users.passwordResetRequired', 'users.locked', 'users.suspended', 'users.pending', 'users.active'])
                ->one();
    }

    private function renderConsent(\League\OAuth2\Server\RequestTypes\AuthorizationRequest $authRequest, $psrRequest, ?string $error): YiiResponse {
        $client = $authRequest->getClient();
        $scopeIds = array_map(fn ($s) => $s->getIdentifier(), $authRequest->getScopes());

        $html = Craft::$app->getView()->renderTemplate('craft-mcp/_oauth/authorize', [
            'clientName' => $client->getName(),
            'scopes' => $scopeIds,
            'state' => (string) $authRequest->getState(),
            'error' => $error,
            'requireConsent' => Mcp::settings()->oauthRequireConsent,
            'query' => [
                'client_id' => $client->getIdentifier(),
                'redirect_uri' => (string) $authRequest->getRedirectUri(),
                'state' => (string) $authRequest->getState(),
                'scope' => implode(' ', $scopeIds),
                'code_challenge' => $authRequest->getCodeChallenge(),
                'code_challenge_method' => $authRequest->getCodeChallengeMethod(),
                'response_type' => 'code',
            ],
        ], \craft\web\View::TEMPLATE_MODE_SITE);

        $response = Craft::$app->getResponse();
        $response->format = YiiResponse::FORMAT_RAW;
        $response->content = $html;
        $response->headers->set('Content-Type', 'text/html; charset=utf-8');

        return $response;
    }

    private function buildPsrRequestForAuthorize(): \Psr\Http\Message\ServerRequestInterface {
        $craftRequest = Craft::$app->getRequest();
        $psr = ServerRequest::fromGlobals();

        // On POST, merge body params into query params so league can re-validate
        // the authorization request using the same field set it saw on GET.
        if ($craftRequest->getIsPost()) {
            $body = $craftRequest->getBodyParams();
            $query = [
                'response_type' => $body['response_type'] ?? 'code',
                'client_id' => $body['client_id'] ?? '',
                'redirect_uri' => $body['redirect_uri'] ?? '',
                'state' => $body['state'] ?? '',
                'scope' => $body['scope'] ?? '',
                'code_challenge' => $body['code_challenge'] ?? '',
                'code_challenge_method' => $body['code_challenge_method'] ?? '',
            ];
            $psr = $psr->withQueryParams($query)->withMethod('GET');
        }

        return $psr;
    }

    private function emitPsrResponse(ResponseInterface $psrResponse): YiiResponse {
        $response = Craft::$app->getResponse();
        $response->format = YiiResponse::FORMAT_RAW;
        $response->statusCode = $psrResponse->getStatusCode();

        foreach ($psrResponse->getHeaders() as $name => $values) {
            $response->headers->remove($name);
            foreach ($values as $value) {
                $response->headers->add($name, $value);
            }
        }

        $response->content = (string) $psrResponse->getBody();

        return $response;
    }

    /**
     * @param mixed[] $data
     */
    private function asJsonResponse(array $data, int $status): YiiResponse {
        $response = Craft::$app->getResponse();
        $response->format = YiiResponse::FORMAT_JSON;
        $response->statusCode = $status;
        $response->data = $data;

        return $response;
    }

    private function checkDcrRateLimit(): bool {
        $ip = Craft::$app->getRequest()->getUserIP() ?? 'unknown';
        $cache = Craft::$app->getCache();
        $key = "mcp.oauth.dcr.rate.{$ip}";
        $count = (int) $cache->get($key);
        if ($count >= 10) {
            return false;
        }
        $cache->set($key, $count + 1, 3600);

        return true;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function decryptRefreshPayload(string $token, string $key): ?array {
        try {
            $decrypted = \Defuse\Crypto\Crypto::decryptWithPassword($token, $key);
            $decoded = json_decode($decrypted, true);
            return is_array($decoded) ? $decoded : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
