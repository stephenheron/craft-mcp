<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\oauth\entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

class ScopeEntity implements ScopeEntityInterface {
    use EntityTrait;
    use ScopeTrait;
}
