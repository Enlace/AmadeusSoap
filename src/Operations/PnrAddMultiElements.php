<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;
use Carbon\Carbon;

class PnrAddMultiElements implements Operation
{
    public function __construct(
        protected string $type,
        protected array $params,
        protected array $remarks = [],
        protected array $retentionConfig = [],
        protected string $contactEmail = 'desarollo@enlaceforte.com',
    ) {}

    public function getOperationName(): string
    {
        return 'PNR_AddMultiElements';
    }

    public function build(): array
    {
        $rfTexts = [
            'create' => 'Added via WebService',
            'end' => 'hotel reservation via WebServices',
            'cancel' => 'hotel CANCELLED via WebServices',
        ];

        $retentionMonths = $this->retentionConfig['months'] ?? 6;
        $cityCode = $this->retentionConfig['city_code'] ?? 'MTY';
        $maxDays = $this->retentionConfig['max_days'] ?? 361;
        $freeText = $this->retentionConfig['free_text'] ?? 'HOTEL BOOKING RETENTION';

        $isMultiDimensional = $this->isMultiArray($this->params);
        $passengerCount = $isMultiDimensional ? count($this->params) : 1;

        // Calculate retention date
        $checkOutDate = null;
        if ($isMultiDimensional && isset($this->params[0]['check_out_date'])) {
            $checkOutDate = $this->params[0]['check_out_date'];
        }

        if ($checkOutDate) {
            $baseDate = Carbon::parse($checkOutDate)->addDays(7);
            $retentionDate = $baseDate->copy()->addMonths($retentionMonths);
            $maxDate = Carbon::now()->addDays($maxDays);
            if ($retentionDate->greaterThan($maxDate)) {
                $retentionDate = $maxDate;
            }
        } else {
            $retentionDate = Carbon::now()->addDays(7);
        }

        $formattedDate = $retentionDate->format('dmy');

        $body = [];

        $body['pnrActions'] = [
            'optionCode' => $this->type === 'create' ? '0' : '11',
        ];

        if ($this->type === 'create') {
            $body['travellerInfo'] = [];
        }

        $dataElementsMaster = [
            'marker1' => null,
            'dataElementsIndiv' => [],
        ];

        $receiveFrom = [
            'elementManagementData' => [
                'segmentName' => 'RF',
            ],
            'freetextData' => [
                'freetextDetail' => [
                    'subjectQualifier' => '3',
                    'type' => 'P22',
                ],
                'longFreetext' => $rfTexts[$this->type],
            ],
        ];

        if ($this->type === 'create') {
            $body['originDestinationDetails'] = [
                'originDestination' => [],
                'itineraryInfo' => [
                    'elementManagementItinerary' => [
                        'segmentName' => 'RU',
                    ],
                    'airAuxItinerary' => [
                        'travelProduct' => [
                            'product' => [
                                'depDate' => $formattedDate,
                            ],
                            'boardpointDetail' => [
                                'cityCode' => $cityCode,
                            ],
                            'company' => [
                                'identification' => '1A',
                            ],
                        ],
                        'messageAction' => [
                            'business' => [
                                'function' => '32',
                            ],
                        ],
                        'relatedProduct' => [
                            'quantity' => $passengerCount,
                            'status' => 'HK',
                        ],
                        'freetextItinerary' => [
                            'freetextDetail' => [
                                'subjectQualifier' => '3',
                            ],
                            'longFreetext' => $freeText,
                        ],
                    ],
                ],
            ];

            if ($isMultiDimensional) {
                foreach ($this->params as $key => $value) {
                    $body['travellerInfo'][] = [
                        'elementManagementPassenger' => [
                            'reference' => [
                                'qualifier' => 'PR',
                                'number' => $key + 1,
                            ],
                            'segmentName' => 'NM',
                        ],
                        'passengerData' => [
                            'travellerInformation' => [
                                'traveller' => [
                                    'surname' => $value['surname'],
                                ],
                                'passenger' => [
                                    'firstName' => $value['name'],
                                    'type' => $value['type'],
                                ],
                            ],
                        ],
                    ];
                }
            } else {
                $body['travellerInfo'] = [
                    'elementManagementPassenger' => [
                        'reference' => [
                            'qualifier' => 'PR',
                            'number' => '1',
                        ],
                        'segmentName' => 'NM',
                    ],
                    'passengerData' => [
                        'travellerInformation' => [
                            'traveller' => [
                                'surname' => $this->params['surname'],
                            ],
                            'passenger' => [
                                'firstName' => $this->params['name'],
                                'type' => $this->params['type'],
                            ],
                        ],
                    ],
                ];
            }

            $body['dataElementsMaster'] = $dataElementsMaster;

            // AP - Contact email
            $body['dataElementsMaster']['dataElementsIndiv'][] = [
                'elementManagementData' => [
                    'reference' => [
                        'qualifier' => 'OT',
                        'number' => '1',
                    ],
                    'segmentName' => 'AP',
                ],
                'freetextData' => [
                    'freetextDetail' => [
                        'subjectQualifier' => '3',
                        'type' => 'P02',
                    ],
                    'longFreetext' => $this->contactEmail,
                ],
            ];

            // RF - Receive From
            $body['dataElementsMaster']['dataElementsIndiv'][] = $receiveFrom;

            // RM - Loyalty Program Comments
            $rmCount = 0;
            if (is_array($this->remarks) && isset($this->remarks['loyalty_programs']) && is_array($this->remarks['loyalty_programs'])) {
                foreach ($this->remarks['loyalty_programs'] as $loyaltyComment) {
                    if (! empty($loyaltyComment) && is_string($loyaltyComment)) {
                        $rmCount++;
                        $rmNumber = 2 + $rmCount;

                        $body['dataElementsMaster']['dataElementsIndiv'][] = [
                            'elementManagementData' => [
                                'reference' => [
                                    'qualifier' => 'OT',
                                    'number' => (string) $rmNumber,
                                ],
                                'segmentName' => 'RM',
                            ],
                            'extendedRemark' => [
                                'structuredRemark' => [
                                    'type' => 'RM',
                                    'freetext' => $loyaltyComment,
                                ],
                            ],
                        ];
                    }
                }
            }

            // TK - Ticket element
            $tkNumber = 2 + $rmCount + 1;
            $body['dataElementsMaster']['dataElementsIndiv'][] = [
                'elementManagementData' => [
                    'reference' => [
                        'qualifier' => 'OT',
                        'number' => (string) $tkNumber,
                    ],
                    'segmentName' => 'TK',
                ],
                'ticketElement' => [
                    'ticket' => [
                        'indicator' => 'OK',
                    ],
                ],
            ];
        } else {
            $body['dataElementsMaster'] = $dataElementsMaster;
            foreach ($receiveFrom as $key => $value) {
                $body['dataElementsMaster']['dataElementsIndiv'][$key] = $value;
            }
        }

        return $body;
    }

    protected function isMultiArray(array $a): bool
    {
        foreach ($a as $v) {
            if (is_array($v)) {
                return true;
            }
        }

        return false;
    }
}
