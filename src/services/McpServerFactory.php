<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\services;

use Craft;
use Mcp\Server;
use Mcp\Server\Builder;
use Mcp\Server\Session\Psr16SessionStore;
use Mcp\Server\Session\SessionStoreInterface;
use Mcp\Server\Transport\StdioTransport;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use stimmt\craft\Mcp\Mcp;
use stimmt\craft\Mcp\models\ResourceDefinition;
use stimmt\craft\Mcp\support\FileLogger;
use stimmt\craft\Mcp\support\Psr11ContainerAdapter;

/**
 * Factory for creating MCP Server instances.
 *
 * Follows DIP: depends on abstractions (ContainerInterface, registries via McpRegistry facade).
 * Follows SRP: sole responsibility is building properly configured Server instances.
 *
 * @author Max van Essen <support@stimmt.digital>
 */
class McpServerFactory {
    public function __construct(
        private readonly ?ContainerInterface $container = new Psr11ContainerAdapter(),
        private readonly ?LoggerInterface $logger = null,
        private readonly ?SessionStoreInterface $sessionStore = null,
    ) {
    }

    /**
     * Create a configured MCP Server instance.
     */
    public function create(): Server {
        $builder = Server::builder()
            ->setServerInfo(
                name: 'Craft CMS MCP Server',
                version: Mcp::getInstance()?->getVersion() ?? '1.0.0',
            )
            ->setInstructions($this->getInstructions())
            ->setContainer($this->container);

        // Tools, prompts and resources are registered manually below via the
        // plugin's own registries so that Mcp::is*Enabled() can gate each one.
        // setDiscovery() is intentionally not used: it would auto-register every
        // #[McpTool]/#[McpPrompt]/#[McpResource] it found, bypassing the
        // enableDangerousTools / disabledTools / disabledPrompts / disabledResources
        // settings.

        if ($this->logger !== null) {
            $builder->setLogger($this->logger);
        }

        if ($this->sessionStore !== null) {
            $builder->setSession($this->sessionStore);
        }

        $this->registerElements($builder);

        return $builder->build();
    }

    /**
     * Create a cache-backed session store for HTTP transport.
     * Uses Craft's configured cache (Redis, Memcached, DB, etc.)
     * so sessions persist across requests and work in multi-server setups.
     */
    public static function createSessionStore(): Psr16SessionStore {
        $adapter = new \stimmt\craft\Mcp\support\CraftCacheAdapter(Craft::$app->getCache());

        return new Psr16SessionStore($adapter, prefix: 'mcp-session-');
    }

    /**
     * Create a StdioTransport for the server.
     */
    public function createTransport(): StdioTransport {
        return new StdioTransport();
    }

    /**
     * Create a file logger that writes to storage/logs/mcp-server.log.
     * This is separate from Craft's logging system.
     */
    public static function createFileLogger(?string $logPath = null): LoggerInterface {
        if ($logPath === null) {
            $logPath = Craft::getAlias('@storage/logs/mcp-server.log');
        }

        return new FileLogger($logPath);
    }

    private function getInstructions(): string {
        return <<<'INSTRUCTIONS'
This MCP server provides access to a Craft CMS installation.

## Available Capabilities

**Tools**: Query and manage entries, assets, users, categories, commerce data
**Resources**: Read configuration, schema information, system state
**Prompts**: Generate content, analyze structure, create entries

## Best Practices

1. Use `list_*` tools to explore available data before making changes
2. Use `get_*` tools to inspect specific items
3. Check schema/fields before creating or updating entries
4. Use read-only queries before mutations
INSTRUCTIONS;
    }

    private function registerElements(Builder $builder): void {
        $this->registerTools($builder);
        $this->registerPrompts($builder);
        $this->registerResources($builder);
    }

    private function registerTools(Builder $builder): void {
        foreach (McpRegistry::tools()->getDefinitions() as $def) {
            if (!Mcp::isToolEnabled($def->name)) {
                continue;
            }

            $builder->addTool(
                handler: [$def->class, $def->method],
                name: $def->name,
                description: $def->description,
            );
        }
    }

    private function registerPrompts(Builder $builder): void {
        foreach (McpRegistry::prompts()->getDefinitions() as $def) {
            if (!Mcp::isPromptEnabled($def->name)) {
                continue;
            }

            $builder->addPrompt(
                handler: [$def->class, $def->method],
                name: $def->name,
                description: $def->description,
            );
        }
    }

    private function registerResources(Builder $builder): void {
        foreach (McpRegistry::resources()->getDefinitions() as $def) {
            if (!Mcp::isResourceEnabled($def->uri)) {
                continue;
            }

            $this->registerResource($builder, $def);
        }
    }

    private function registerResource(Builder $builder, ResourceDefinition $def): void {
        if ($def->isTemplate) {
            $builder->addResourceTemplate(
                handler: [$def->class, $def->method],
                uriTemplate: $def->uri,
                name: $def->name,
                description: $def->description,
                mimeType: $def->mimeType,
            );

            return;
        }

        $builder->addResource(
            handler: [$def->class, $def->method],
            uri: $def->uri,
            name: $def->name,
            description: $def->description,
            mimeType: $def->mimeType,
        );
    }
}
