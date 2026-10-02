<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class PnrCancel implements Operation
{
    public function __construct(
        protected PnrCancelParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'PNR_Cancel';
    }

    public function build(): array
    {
        $cancelElements = [];

        if (is_array($this->params->segmentNumber)) {
            foreach ($this->params->segmentNumber as $segmentNumber) {
                $cancelElements[] = [
                    'entryType' => 'E',
                    'element' => [
                        'identifier' => 'ST',
                        'number' => $segmentNumber,
                    ],
                ];
            }
        } else {
            $cancelElements = [
                'entryType' => 'E',
                'element' => [
                    'identifier' => 'ST',
                    'number' => $this->params->segmentNumber,
                ],
            ];
        }

        return [
            'pnrActions' => [
                'optionCode' => '0',
            ],
            'cancelElements' => $cancelElements,
        ];
    }
}
