<?php

namespace Aldogtz\AmadeusSoap\Wsdl;

use Aldogtz\AmadeusSoap\Exceptions\OperationNotFoundException;

class OperationRegistry
{
    /** @var array<string, OperationMetadata> */
    protected array $operations = [];

    public function register(string $name, OperationMetadata $metadata): void
    {
        $this->operations[$name] = $metadata;
    }

    public function has(string $name): bool
    {
        return isset($this->operations[$name]);
    }

    /**
     * @throws OperationNotFoundException
     */
    public function get(string $name): OperationMetadata
    {
        if (! $this->has($name)) {
            throw OperationNotFoundException::forOperation($name);
        }

        return $this->operations[$name];
    }

    /** @return array<string, OperationMetadata> */
    public function all(): array
    {
        return $this->operations;
    }
}
