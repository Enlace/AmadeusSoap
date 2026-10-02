<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class HotelSell implements Operation
{
    public function __construct(
        protected array $params,
    ) {}

    public function getOperationName(): string
    {
        return 'Hotel_Sell';
    }

    public function build(): array
    {
        $travelAgentRef = $this->params['travelAgentRef'];

        $body = [
            'systemIdentifier' => [
                'deliveringSystem' => [
                    'companyId' => 'WEBS',
                ],
            ],
            'travelAgentRef' => [
                'status' => 'APE',
                'reference' => [
                    'type' => 'OT',
                    'value' => $travelAgentRef,
                ],
            ],
            'roomStayData' => [],
        ];

        $isMultiDimensional = $this->isMultiRoom();

        if (! $isMultiDimensional) {
            $body['roomStayData'] = $this->buildSingleRoom($this->params);
        } else {
            foreach ($this->params as $key => $param) {
                if ($key !== 'travelAgentRef' && is_array($param)) {
                    $body['roomStayData'][] = $this->buildSingleRoom($param);
                }
            }
        }

        return $body;
    }

    protected function buildSingleRoom(array $params): array
    {
        $representativeParties = [];
        $guestList = [];

        $passengerRefs = $params['passengerReference'];

        if (isset($passengerRefs['value'])) {
            // Single passenger reference
            $representativeParties = [
                'occupantList' => [
                    'passengerReference' => [
                        'type' => $passengerRefs['type'],
                        'value' => $passengerRefs['value'],
                    ],
                ],
            ];
            $guestList = [
                'occupantList' => [
                    'passengerReference' => [
                        'type' => $passengerRefs['type'] === 'BHO' ? 'RMO' : 'ROP',
                        'value' => $passengerRefs['value'],
                    ],
                ],
            ];
        } else {
            // Multiple passenger references
            foreach ($passengerRefs as $passenger) {
                $representativeParties[] = [
                    'occupantList' => [
                        'passengerReference' => [
                            'type' => $passenger['type'],
                            'value' => $passenger['value'],
                        ],
                    ],
                ];
                $guestList[] = [
                    'occupantList' => [
                        'passengerReference' => [
                            'type' => $passenger['type'] === 'BHO' ? 'RMO' : 'ROP',
                            'value' => $passenger['value'],
                        ],
                    ],
                ];
            }
        }

        return [
            'markerRoomStayData' => null,
            'globalBookingInfo' => [
                'markerGlobalBookingInfo' => [
                    'hotelReference' => [
                        'chainCode' => (string) $params['chainCode'],
                        'cityCode' => (string) $params['cityCode'],
                        'hotelCode' => substr((string) $params['hotelCode'], -3),
                    ],
                ],
                'representativeParties' => $representativeParties,
            ],
            'roomList' => [
                'markerRoomstayQuery' => null,
                'roomRateDetails' => [
                    'marker' => null,
                    'hotelProductReference' => [
                        'referenceDetails' => [
                            'type' => 'BC',
                            'value' => $params['bookingCode'],
                        ],
                    ],
                    'markerOfExtra' => null,
                ],
                'guaranteeOrDeposit' => [
                    'paymentInfo' => [
                        'paymentDetails' => [
                            'formOfPaymentCode' => '1',
                            'paymentType' => $params['paymentType'],
                            'serviceToPay' => '3',
                        ],
                    ],
                    'groupCreditCardInfo' => [
                        'creditCardInfo' => [
                            'ccInfo' => $this->buildCardInfo($params),
                        ],
                    ],
                ],
                'guestList' => $guestList,
            ],
        ];
    }

    /**
     * The guarantee card. An explicit ccHolderName is sent as given; without
     * one it is "firstName surname". firstName/surname are only sent when the
     * caller passes either of them: a room keyed by ccHolderName alone is the
     * shape BookingV2 sells multi-room bookings with in production.
     */
    protected function buildCardInfo(array $params): array
    {
        $hasName = array_key_exists('firstName', $params) || array_key_exists('surname', $params);
        $firstName = (string) ($params['firstName'] ?? '');
        $surname = (string) ($params['surname'] ?? '');

        $card = [
            'vendorCode' => $params['vendorCode'],
            'cardNumber' => $params['cardNumber'],
            'securityId' => $params['securityId'],
            'expiryDate' => $params['expiryDate'],
            'ccHolderName' => trim((string) ($params['ccHolderName'] ?? $firstName.' '.$surname)),
        ];

        if ($hasName) {
            $card['surname'] = $surname;
            $card['firstName'] = $firstName;
        }

        return $card;
    }

    protected function isMultiRoom(): bool
    {
        foreach ($this->params as $key => $value) {
            if ($key !== 'travelAgentRef' && is_array($value) && isset($value['chainCode'])) {
                return true;
            }
        }

        return false;
    }
}
