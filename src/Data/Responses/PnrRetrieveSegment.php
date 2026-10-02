<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

final readonly class PnrRetrieveSegment
{
    public function __construct(
        public string $segmentNumber,
    ) {}
}
