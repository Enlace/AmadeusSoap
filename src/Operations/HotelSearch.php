<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Operations\Concerns\BuildsGuestCounts;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterStrategy;
use DOMDocument;
use DOMXPath;
use Illuminate\Support\Str;
use SoapVar;

class HotelSearch implements Operation
{
    use BuildsGuestCounts;

    public function __construct(
        protected HotelSearchParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'Hotel_MultiSingleAvailability';
    }

    public function isStateful(SoapVar $bodyVar): bool
    {
        if ($this->params->type === 'multi' && $this->params->hotelCode === null) {
            // Multi search by city/geo is stateless
            if ($this->params->latitude !== null && $this->params->longitude !== null) {
                return false;
            }
            if ($this->params->hotelCityCode !== null) {
                return false;
            }
        }

        // Single hotel by code is stateful
        return true;
    }

    public function build(): array
    {
        $searchData = $this->buildSearchCriteria();
        $guestCount = $this->buildGuestCounts($this->params->guestCount, $this->params->children);

        $availRequestSegmentAttributes = [
            'InfoSource' => $this->params->infoSource,
        ];

        if ($this->params->moreDataEchoToken !== null && $this->params->hotelCode === null) {
            $availRequestSegmentAttributes['MoreDataEchoToken'] = $this->params->moreDataEchoToken;
        }

        // In the OTA schema these belong on OTA_HotelAvailRQ as attributes, not
        // as child elements. Amadeus answers " 11|Session|" when they arrive as
        // elements.
        $rootAttributes = [
            'EchoToken' => 'MultiSingle',
            'Version' => '4.000',
            'PrimaryLangID' => 'EN',
            'SummaryOnly' => 'true',
            'AvailRatesOnly' => 'true',
            'RateRangeOnly' => 'true',
            'SearchCacheLevel' => $this->params->searchCacheLevel,
            'RateDetailsInd' => 'true',
            'RequestedCurrency' => $this->params->currency ?? 'MXN',
            'MaxResponses' => $this->params->maxResponses,
            'ExactMatchOnly' => 'true',
        ];

        if ($this->params->sortOrder !== null) {
            $rootAttributes['SortOrder'] = $this->params->sortOrder;
        }

        $body = [
            '_attributes' => $rootAttributes,
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => $availRequestSegmentAttributes,
                    'HotelSearchCriteria' => [
                        'Criterion' => array_merge(
                            ['_attributes' => ['ExactMatch' => 'true']],
                            $searchData
                        ),
                    ],
                ],
            ],
        ];

        if ($this->params->type === 'multi' && $this->params->hotelName === null) {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['_attributes'] = [
                'AvailableOnlyIndicator' => 'true',
                'BestOnlyIndicator' => $this->shouldUseBestOnly() ? 'true' : 'false',
            ];
        }

        // Rating filter
        if ($this->params->rating !== null && $this->params->hotelCode === null) {
            if ($this->params->rating == 5) {
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = [
                    '_attributes' => ['Provider' => 'LSR', 'Rating' => $this->params->rating],
                ];
            } else {
                $awards = [];
                for ($i = $this->params->rating; $i <= 5; $i++) {
                    $awards[] = [
                        '_attributes' => ['Provider' => 'LSR', 'Rating' => (string) $i],
                    ];
                }
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = $awards;
            }
        }

        // Stay date range
        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['StayDateRange'] = [
            '_attributes' => ['Start' => $this->params->start, 'End' => $this->params->end],
        ];

        // Rate plan candidates
        if ($this->params->hotelName === null) {
            $ratePlanCodes = $this->getRatePlanCodes();

            if (! empty($ratePlanCodes)) {
                $ratePlanCandidate = array_map(
                    fn ($code) => ['_attributes' => ['RatePlanCode' => $code]],
                    $ratePlanCodes
                );

                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RatePlanCandidates'] = [
                    'RatePlanCandidate' => $ratePlanCandidate,
                ];
            }
        }

        // Rate range
        if (($this->params->maxRate !== null || $this->params->minRate !== null) && $this->params->hotelCode === null) {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RateRange'] = [
                '_attributes' => [
                    'CurrencyCode' => $this->params->currency ?? 'MXN',
                    'MaxRate' => $this->params->maxRate,
                    'MinRate' => $this->params->minRate ?? '0',
                ],
            ];
        }

        // Room stay candidates
        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RoomStayCandidates'] = [
            'RoomStayCandidate' => [
                '_attributes' => [
                    'RoomID' => '1',
                    'Quantity' => $this->params->type === 'multi' ? '1' : $this->params->quantity,
                ],
                'GuestCounts' => [
                    '_attributes' => ['IsPerRoom' => 'true'],
                    'GuestCount' => $guestCount,
                ],
            ],
        ];

        return $body;
    }

    protected function buildSearchCriteria(): array
    {
        $searchData = [];

        if ($this->params->latitude !== null && $this->params->longitude !== null) {
            $latitude = $this->formatCoordinate($this->params->latitude);
            $longitude = $this->formatCoordinate($this->params->longitude);

            $searchData['Position'] = [
                '_attributes' => [
                    'Latitude' => $latitude,
                    'Longitude' => $longitude,
                ],
            ];

            $searchData['Radius'] = [
                '_attributes' => [
                    'Distance' => $this->params->distance,
                    'DistanceMeasure' => 'DIS',
                    'UnitOfMeasureCode' => '2',
                ],
            ];
        } else {
            $hotelRefAttributes = [];

            if ($this->params->hotelCityCode !== null) {
                $hotelRefAttributes['HotelCityCode'] = $this->params->hotelCityCode;
            }
            if ($this->params->hotelName !== null) {
                $hotelRefAttributes['HotelName'] = $this->params->hotelName;
                $hotelRefAttributes['ExtendedCitySearchIndicator'] = '1';
            }
            if ($this->params->hotelCode !== null) {
                $hotelRefAttributes['HotelCode'] = $this->params->hotelCode;
            }
            if ($this->params->chainCode !== null) {
                $hotelRefAttributes['ChainCode'] = $this->params->chainCode;
            }

            $searchData['HotelRef'] = [
                '_attributes' => $hotelRefAttributes,
            ];
        }

        return $searchData;
    }

    protected function formatCoordinate(string $value): string
    {
        if (Str::contains($value, '.')) {
            $parts = explode('.', $value);
            $decimal = $parts[1];

            if (strlen($decimal) > 5) {
                $decimal = substr($decimal, 0, 5);
            } elseif (strlen($decimal) < 5) {
                $decimal = str_pad($decimal, 5, '0');
            }

            return $parts[0].$decimal;
        }

        return $value;
    }

    /**
     * Determine if BestOnlyIndicator should be true.
     */
    protected function shouldUseBestOnly(): bool
    {
        return $this->params->rateStrategy === RateFilterStrategy::BEST_ONLY;
    }

    /**
     * Rate plan codes sent as RatePlanCandidates.
     *
     * @return string[]
     */
    protected function getRatePlanCodes(): array
    {
        return is_array($this->params->rateCode)
            ? $this->params->rateCode
            : [$this->params->rateCode];
    }
}
