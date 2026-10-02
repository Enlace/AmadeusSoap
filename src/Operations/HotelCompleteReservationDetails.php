<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class HotelCompleteReservationDetails implements Operation
{
    public function __construct(
        protected HotelCompleteReservationDetailsParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'Hotel_CompleteReservationDetails';
    }

    public function build(): array
    {
        return [
            'retrievalKeyGroup' => [
                'retrievalKey' => [
                    'reservation' => [
                        'companyId' => '1A',
                        'controlNumber' => $this->params->pnrNumber,
                        'controlType' => 'P',
                    ],
                ],
                'tattooID' => [
                    'referenceDetails' => [
                        'type' => 'S',
                        'value' => $this->params->segmentNumber,
                    ],
                ],
            ],
        ];
    }
}
