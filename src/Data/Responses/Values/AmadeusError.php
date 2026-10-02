<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class AmadeusError
{
    public function __construct(
        public string $message,
        public string $code = '',
        public string $type = 'error',
    ) {}
}
