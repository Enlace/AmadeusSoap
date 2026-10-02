<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Operations\Concerns\BuildsGuestCounts;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class HotelPricing implements Operation
{
    use BuildsGuestCounts;

    public function __construct(
        protected HotelPricingParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'Hotel_EnhancedPricing';
    }

    public function build(): array
    {
        $guestCount = $this->buildGuestCounts($this->params->guestCount, $this->params->children);

        return [
            // OTA_HotelAvailRQ carries these as attributes, not child elements
            '_attributes' => [
                'EchoToken' => 'Pricing',
                'Version' => '4.000',
                'PrimaryLangID' => 'EN',
                'SummaryOnly' => 'false',
                'RateRangeOnly' => 'false',
                'RequestedCurrency' => 'MXN',
            ],
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => ['InfoSource' => 'Distribution'],
                    'HotelSearchCriteria' => [
                        'Criterion' => [
                            '_attributes' => ['ExactMatch' => 'true'],
                            'HotelRef' => [
                                '_attributes' => ['HotelCode' => $this->params->hotelCode],
                            ],
                            'StayDateRange' => [
                                '_attributes' => [
                                    'Start' => $this->params->start,
                                    'End' => $this->params->end,
                                ],
                            ],
                            'RatePlanCandidates' => [
                                'RatePlanCandidate' => [
                                    '_attributes' => ['RatePlanCode' => $this->params->ratePlanCode],
                                ],
                            ],
                            'RoomStayCandidates' => [
                                'RoomStayCandidate' => [
                                    '_attributes' => [
                                        'BookingCode' => $this->params->bookingCode,
                                        'RoomTypeCode' => $this->params->roomTypeCode,
                                        'RoomID' => '1',
                                        'Quantity' => $this->params->quantity,
                                    ],
                                    'GuestCounts' => [
                                        '_attributes' => ['IsPerRoom' => $this->params->isPerRoom],
                                        'GuestCount' => $guestCount,
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }
}
