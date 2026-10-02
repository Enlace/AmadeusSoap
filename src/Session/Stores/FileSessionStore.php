<?php

namespace Aldogtz\AmadeusSoap\Session\Stores;

use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionData;

class FileSessionStore implements SessionStore
{
    public function __construct(
        protected string $path,
        protected string $prefix = 'amadeus_session_',
        protected int $ttl = 900,
    ) {
        if (! is_dir($this->path)) {
            mkdir($this->path, 0755, true);
        }
    }

    public function get(string $key): ?SessionData
    {
        $filePath = $this->filePath($key);

        if (! file_exists($filePath)) {
            return null;
        }

        // Check TTL via file modification time
        if ((time() - filemtime($filePath)) > $this->ttl) {
            $this->forget($key);

            return null;
        }

        $contents = file_get_contents($filePath);

        if ($contents === false) {
            return null;
        }

        return SessionData::tryFromArray(json_decode($contents, true));
    }

    public function put(string $key, SessionData $data): void
    {
        file_put_contents(
            $this->filePath($key),
            json_encode($data->toArray()),
            LOCK_EX,
        );
    }

    public function forget(string $key): void
    {
        $filePath = $this->filePath($key);

        if (file_exists($filePath)) {
            unlink($filePath);
        }
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    /**
     * Build the full file path for a session key.
     */
    protected function filePath(string $key): string
    {
        // Sanitize key to be filesystem-safe
        $safeKey = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $key);

        return $this->path.DIRECTORY_SEPARATOR.$this->prefix.$safeKey.'.json';
    }
}
