<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

/**
 * An OTA Warning. Multi-hotel searches report one per provider, e.g.
 * Tag="CLS" Status="PRV.4"; Tag="OK" is the marker of a usable reply.
 */
final readonly class Warning
{
    public function __construct(
        public string $type,
        public string $code,
        public string $status,
        public string $tag,
        public string $text,
    ) {}
}
