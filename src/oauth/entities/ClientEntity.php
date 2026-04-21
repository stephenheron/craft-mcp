<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface {
    use ClientTrait;
    use EntityTrait;

    public function setName(string $name): void {
        $this->name = $name;
    }

    /**
     * @param string|string[] $redirectUri
     */
    public function setRedirectUri(string|array $redirectUri): void {
        $this->redirectUri = $redirectUri;
    }

    public function setConfidential(bool $isConfidential): void {
        $this->isConfidential = $isConfidential;
    }
}
