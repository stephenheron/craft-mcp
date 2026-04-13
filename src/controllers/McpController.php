<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\controllers;

use Craft;
use craft\web\Controller;
use GuzzleHttp\Psr7\ServerRequest;
use Mcp\Server\Transport\StreamableHttpTransport;
use Psr\Http\Message\ResponseInterface;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\services\McpServerFactory;

/**
 * Handles MCP requests over Streamable HTTP transport.
 *
 * Exposes the MCP server as a web endpoint within Craft's request lifecycle,
 * allowing MCP clients to connect via HTTP instead of stdio.
 *
 * @author Stephen Heron
 */
class McpController extends Controller {
    /**
     * @inheritdoc
     */
    protected array|bool|int $allowAnonymous = true;

    /**
     * @inheritdoc
     */
    public $enableCsrfValidation = false;

    /**
     * Handle an incoming MCP request (POST, DELETE, OPTIONS).
     */
    public function actionIndex(): void {
        if (!Mcp::isEnabled()) {
            $this->sendJsonError('MCP is disabled', 503);
            return;
        }

        $settings = Mcp::settings();
        if (!$settings->enableHttpTransport) {
            $this->sendJsonError('HTTP transport is disabled', 403);
            return;
        }

        // IP allowlist check
        if (!empty($settings->allowedIps)) {
            $ip = Craft::$app->getRequest()->getUserIP();
            if (!in_array($ip, $settings->allowedIps, true)) {
                $this->sendJsonError('Forbidden', 403);
                return;
            }
        }

        // Build PSR-7 request from PHP globals
        $psrRequest = ServerRequest::fromGlobals();

        // Build MCP server and HTTP transport with persistent sessions
        $logger = McpServerFactory::createFileLogger();
        $sessionStore = McpServerFactory::createSessionStore();
        $factory = new McpServerFactory(logger: $logger, sessionStore: $sessionStore);
        $server = $factory->create();
        $transport = new StreamableHttpTransport(
            request: $psrRequest,
            logger: $logger,
        );

        /** @var ResponseInterface $psrResponse */
        $psrResponse = $server->run($transport);

        // Emit the PSR-7 response directly, bypassing Craft's response handling
        $this->emitPsrResponse($psrResponse);
    }

    /**
     * Emit a PSR-7 response directly to PHP output.
     */
    private function emitPsrResponse(ResponseInterface $response): void {
        // Disable output buffering for SSE streaming
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        // Status line
        http_response_code($response->getStatusCode());

        // Headers
        foreach ($response->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                header("{$name}: {$value}", false);
            }
        }

        // Body - for CallbackStream this triggers the SSE echo/flush() callback
        echo (string) $response->getBody();

        exit(0);
    }

    /**
     * Send a JSON error response and terminate.
     */
    private function sendJsonError(string $message, int $statusCode): void {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode(['error' => $message]);

        exit(0);
    }
}
