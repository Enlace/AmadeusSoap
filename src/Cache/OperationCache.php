<?php

namespace Aldogtz\AmadeusSoap\Cache;

use Illuminate\Contracts\Cache\Repository;

/**
 * Caches the raw response XML of stateless, read-only operations.
 *
 * Only the XML string is stored: response DTOs hold DOM objects, which cannot
 * be serialized. The caller decides when a call is cacheable — stateful calls
 * must never be cached, because their response carries the Amadeus session
 * that the following pricing/sell/PNR calls continue.
 *
 * Store failures are reported and swallowed: a cache outage turns into
 * misses, never into a failed Amadeus call.
 */
class OperationCache
{
    /**
     * @param  array<string, int>  $ttls  Operation name => TTL in seconds. Operations
     *                                    missing here (or with TTL <= 0) are not cached.
     * @param  string  $scope  Isolates entries per Amadeus office: rates and
     *                         availability differ between offices.
     */
    public function __construct(
        protected Repository $store,
        protected array $ttls = [],
        protected string $prefix = 'amadeus_cache',
        protected string $scope = '',
    ) {}

    public function isCacheable(string $operation): bool
    {
        return ($this->ttls[$operation] ?? 0) > 0;
    }

    /**
     * Get the cached response XML for an operation and request body.
     */
    public function get(string $operation, string $body): ?string
    {
        if (! $this->isCacheable($operation)) {
            return null;
        }

        $xml = rescue(fn () => $this->store->get($this->key($operation, $body)));

        return is_string($xml) ? $xml : null;
    }

    /**
     * Store the response XML for an operation and request body.
     */
    public function put(string $operation, string $body, string $responseXml): void
    {
        if (! $this->isCacheable($operation)) {
            return;
        }

        rescue(fn () => $this->store->put($this->key($operation, $body), $responseXml, $this->ttls[$operation]));
    }

    /**
     * Invalidate every cached response.
     *
     * Works on any cache store (no tags needed): bumping the generation makes
     * all existing keys unreachable, and they expire on their own TTL.
     */
    public function flush(): void
    {
        $this->store->forever($this->generationKey(), $this->generation() + 1);
    }

    protected function key(string $operation, string $body): string
    {
        return sprintf(
            '%s:%d:%s:%s',
            $this->prefix,
            $this->generation(),
            $operation,
            hash('xxh128', $this->scope."\n".$body),
        );
    }

    protected function generation(): int
    {
        return (int) $this->store->get($this->generationKey(), 0);
    }

    protected function generationKey(): string
    {
        return $this->prefix.':generation';
    }
}
