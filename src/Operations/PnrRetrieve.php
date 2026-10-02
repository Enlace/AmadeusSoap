<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class PnrRetrieve implements Operation
{
    public function __construct(
        protected PnrRetrieveParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'PNR_Retrieve';
    }

    public function build(): array
    {
        return [
            'retrievalFacts' => [
                'retrieve' => [
                    'type' => '2',
                ],
                'reservationOrProfileIdentifier' => [
                    'reservation' => [
                        'controlNumber' => $this->params->pnrNumber,
                    ],
                ],
            ],
        ];
    }
}
