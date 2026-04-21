<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\support;

use GuzzleHttp\Psr7\Response as PsrResponse;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Carries a PSR-7 401/403 response for the McpController to emit when
 * an incoming request lacks valid OAuth credentials.
 */
final class OAuthGuardException extends RuntimeException {
    public function __construct(
        private readonly int $status,
        private readonly string $wwwAuthenticate,
        private readonly string $body = '',
    ) {
        parent::__construct($body !== '' ? $body : 'OAuth authorization failed');
    }

    public function toPsrResponse(): ResponseInterface {
        $headers = [
            'WWW-Authenticate' => $this->wwwAuthenticate,
            'Content-Type' => 'application/json',
        ];

        $body = $this->body !== '' ? $this->body : json_encode(['error' => 'invalid_token']);

        return new PsrResponse($this->status, $headers, $body);
    }
}
