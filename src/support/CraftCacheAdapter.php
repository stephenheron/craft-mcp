<?php

declare(strict_types=1);

namespace stimmt\craft\Mcp\support;

use Psr\SimpleCache\CacheInterface;
use yii\caching\CacheInterface as YiiCacheInterface;

/**
 * Adapts Craft/Yii2's cache component to PSR-16 SimpleCache.
 *
 * This allows the MCP session store to use whatever cache backend
 * Craft is configured with (Redis, Memcached, DB, etc.), making
 * sessions work across multiple servers.
 */
class CraftCacheAdapter implements CacheInterface {
    public function __construct(private readonly YiiCacheInterface $cache) {
    }

    public function get(string $key, mixed $default = null): mixed {
        $value = $this->cache->get($key);

        return $value === false ? $default : $value;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool {
        $duration = $this->ttlToSeconds($ttl);

        return $this->cache->set($key, $value, $duration);
    }

    public function delete(string $key): bool {
        return $this->cache->delete($key);
    }

    public function clear(): bool {
        return $this->cache->flush();
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable {
        $results = [];
        foreach ($keys as $key) {
            $results[$key] = $this->get($key, $default);
        }

        return $results;
    }

    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool {
        $success = true;
        foreach ($values as $key => $value) {
            if (!$this->set($key, $value, $ttl)) {
                $success = false;
            }
        }

        return $success;
    }

    public function deleteMultiple(iterable $keys): bool {
        $success = true;
        foreach ($keys as $key) {
            if (!$this->delete($key)) {
                $success = false;
            }
        }

        return $success;
    }

    public function has(string $key): bool {
        return $this->cache->exists($key);
    }

    private function ttlToSeconds(\DateInterval|int|null $ttl): int {
        if ($ttl === null) {
            return 0;
        }

        if ($ttl instanceof \DateInterval) {
            return (int) (new \DateTime())->setTimestamp(0)->add($ttl)->getTimestamp();
        }

        return $ttl;
    }
}
