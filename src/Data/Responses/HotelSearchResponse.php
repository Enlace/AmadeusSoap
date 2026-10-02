<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CurrencyConversion;
use Aldogtz\AmadeusSoap\Data\Responses\Values\DailyRate;
use Aldogtz\AmadeusSoap\Data\Responses\Values\MealsIncluded;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RoomTotal;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilter;
use Aldogtz\AmadeusSoap\RateFiltering\RateFilterCriteria;

final class HotelSearchResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  HotelResult[]  $hotels
     * @param  RoomStayResult[]  $roomStays  Room stays for single-hotel search
     * @param  CurrencyConversion[]  $currencyConversions
     */
    public function __construct(
        public readonly bool $ok,
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly array $hotels,
        public readonly array $roomStays,
        public readonly array $currencyConversions,
        public readonly ?string $moreIndicator,
        public readonly AmadeusResponse $raw,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = self::parseOtaErrors($response);
        $ok = $response->hasOkWarning();

        $hotels = [];
        $roomStays = [];
        $currencyConversions = [];

        if ($ok) {
            $hotels = self::parseHotels($response);
            $roomStays = self::parseRoomStays($response);
            $currencyConversions = self::parseCurrencyConversions($response);
        }

        $moreIndicator = self::str($response, '//res:RoomStays/@MoreIndicator') ?: null;

        return new self(
            ok: $ok,
            hasErrors: count($errors) > 0,
            errors: $errors,
            hotels: $hotels,
            roomStays: $roomStays,
            currencyConversions: $currencyConversions,
            moreIndicator: $moreIndicator,
            raw: $response,
        );
    }

    /**
     * Append a further page of results to this one.
     *
     * Amadeus numbers RPHs per response, so a second page can reuse "0", "1"
     * and so on. When that happens the incoming page's RPHs are rewritten —
     * on both the hotels and the room stays — so HotelResult::roomStays()
     * keeps pairing each property with its own rates.
     *
     * `raw` stays the first page's; use the individual responses if you need
     * per-page XML. `moreIndicator` becomes the incoming page's, so an
     * exhausted sequence ends up null.
     */
    public function mergePage(self $next): self
    {
        $used = [];
        foreach ($this->roomStays as $roomStay) {
            $used[$roomStay->rph] = true;
        }

        $remap = self::rphRemapFor($next->roomStays, $used);

        $nextRoomStays = $remap === []
            ? $next->roomStays
            : array_map(
                fn (RoomStayResult $roomStay) => isset($remap[$roomStay->rph])
                    ? $roomStay->withRph($remap[$roomStay->rph])
                    : $roomStay,
                $next->roomStays,
            );

        $nextHotels = $remap === []
            ? $next->hotels
            : array_map(
                fn (HotelResult $hotel) => $hotel->withRoomStayRPHs(array_map(
                    fn (string $rph) => $remap[$rph] ?? $rph,
                    $hotel->roomStayRPHs,
                )),
                $next->hotels,
            );

        return new self(
            ok: $this->ok || $next->ok,
            hasErrors: $this->hasErrors || $next->hasErrors,
            errors: array_merge($this->errors, $next->errors),
            hotels: array_merge($this->hotels, $nextHotels),
            roomStays: array_merge($this->roomStays, $nextRoomStays),
            currencyConversions: $this->currencyConversions !== []
                ? $this->currencyConversions
                : $next->currencyConversions,
            moreIndicator: $next->moreIndicator,
            raw: $this->raw,
        );
    }

    /**
     * Copy of this response keeping only the room stays that match the criteria.
     *
     * Meant for searches by hotel code, where every room stay belongs to the
     * same hotel (and currency). Hotels and the raw response are left untouched.
     */
    public function filterRoomStays(RateFilterCriteria $criteria): self
    {
        return new self(
            ok: $this->ok,
            hasErrors: $this->hasErrors,
            errors: $this->errors,
            hotels: $this->hotels,
            roomStays: (new RateFilter($criteria))->apply($this->roomStays),
            currencyConversions: $this->currencyConversions,
            moreIndicator: $this->moreIndicator,
            raw: $this->raw,
        );
    }

    /**
     * Build a rename map for incoming RPHs that clash with ones already held.
     *
     * @param  RoomStayResult[]  $incoming
     * @param  array<string, true>  $used
     * @return array<string, string> old RPH => new RPH, empty when no clash
     */
    private static function rphRemapFor(array $incoming, array $used): array
    {
        $clash = false;
        foreach ($incoming as $roomStay) {
            if (isset($used[$roomStay->rph])) {
                $clash = true;
                break;
            }
        }

        if (! $clash) {
            return [];
        }

        // Find a prefix that collides with nothing already in play
        $page = 1;
        do {
            $prefix = 'p'.$page.':';
            $free = true;
            foreach ($incoming as $roomStay) {
                if (isset($used[$prefix.$roomStay->rph])) {
                    $free = false;
                    break;
                }
            }
            $page++;
        } while (! $free && $page < 1000);

        $remap = [];
        foreach ($incoming as $roomStay) {
            $remap[$roomStay->rph] = $prefix.$roomStay->rph;
        }

        return $remap;
    }

    /**
     * @return HotelResult[]
     */
    private static function parseHotels(AmadeusResponse $response): array
    {
        $hotels = [];
        $hotelNodes = self::nodes($response, '//res:HotelStays/res:HotelStay');

        foreach ($hotelNodes as $node) {
            $roomStayRPH = self::str($response, './@RoomStayRPH', $node);

            // Amadeus lists every rate the property offers in a single
            // space-separated attribute (RoomStayRPH="0 1 2"). Matching the
            // raw value against @RPH finds nothing, which used to leave the
            // summary fields empty for any property with more than one rate.
            $roomStayRPHs = preg_split('/\s+/', trim($roomStayRPH), -1, PREG_SPLIT_NO_EMPTY) ?: [];

            // Summary fields describe the first rate, which is the best one
            // when Amadeus applies BestOnlyIndicator.
            $primaryRPH = $roomStayRPHs[0] ?? '';
            // RoomStays is a sibling of HotelStays, so this looks up from the
            // document root rather than the HotelStay context node.
            $roomStay = $primaryRPH === ''
                ? null
                : self::nodes($response, '//res:RoomStay[@RPH = '.self::xpathLiteral($primaryRPH).']')->item(0);

            $hotels[] = new HotelResult(
                hotelCode: self::str($response, './res:BasicPropertyInfo/@HotelCode', $node),
                hotelName: self::str($response, './res:BasicPropertyInfo/@HotelName', $node),
                chainCode: self::str($response, './res:BasicPropertyInfo/@ChainCode', $node),
                ratingCode: self::str($response, './res:BasicPropertyInfo/@HotelSegmentCategoryCode', $node),
                countryCode: self::str($response, './res:BasicPropertyInfo/res:Address/res:CountryName/@Code', $node),
                roomStayRPH: $roomStayRPH,
                total: self::parseRoomTotal($response, $roomStay),
                dailyRates: self::parseDailyRates($response, $roomStay),
                ratePlanCode: $roomStay === null ? '' : self::str($response, './res:RatePlans/res:RatePlan/@RatePlanCode', $roomStay),
                ratePlanCategory: $roomStay === null ? '' : self::str($response, './res:RoomRates/res:RoomRate/@RatePlanCategory', $roomStay),
                start: $roomStay === null ? '' : self::str($response, './res:TimeSpan/@Start', $roomStay),
                end: $roomStay === null ? '' : self::str($response, './res:TimeSpan/@End', $roomStay),
                roomStayRPHs: $roomStayRPHs,
            );
        }

        return $hotels;
    }

    /**
     * Quote a value for safe interpolation into an XPath expression.
     */
    private static function xpathLiteral(string $value): string
    {
        if (! str_contains($value, "'")) {
            return "'".$value."'";
        }

        if (! str_contains($value, '"')) {
            return '"'.$value.'"';
        }

        return 'concat('.implode(", \"'\", ", array_map(
            fn (string $part) => "'".$part."'",
            explode("'", $value),
        )).')';
    }

    /**
     * @return RoomStayResult[]
     */
    private static function parseRoomStays(AmadeusResponse $response): array
    {
        $roomStays = [];
        $roomStayNodes = self::nodes($response, '//res:RoomStay');

        // A property lists its rates in HotelStay@RoomStayRPH ("0 1 2")
        $hotelByRph = [];
        foreach (self::nodes($response, '//res:HotelStays/res:HotelStay') as $hotelStay) {
            $hotelCode = self::str($response, './res:BasicPropertyInfo/@HotelCode', $hotelStay);

            foreach (preg_split('/\s+/', self::str($response, './@RoomStayRPH', $hotelStay), -1, PREG_SPLIT_NO_EMPTY) as $rph) {
                $hotelByRph[$rph] = $hotelCode;
            }
        }

        foreach ($roomStayNodes as $node) {
            $rph = self::str($response, './@RPH', $node);
            [$adults, $children] = self::parseGuestCounts($response, $node);
            $total = self::parseRoomTotal($response, $node);
            $dailyRates = self::parseDailyRates($response, $node);

            $featureNodes = self::nodes($response, './res:RoomRates/res:RoomRate/res:Features/res:Feature', $node);
            $amenities = [];
            foreach ($featureNodes as $featureNode) {
                $amenity = self::str($response, './@RoomAmenity', $featureNode);
                if ($amenity !== '') {
                    $amenities[] = $amenity;
                }
            }

            // null when Amadeus does not say (some rates only describe the penalty in text)
            $nonRefundable = self::otaBoolean($response, './res:RatePlans/res:RatePlan/res:CancelPenalties/res:CancelPenalty/@NonRefundable', $node);

            $roomStays[] = new RoomStayResult(
                rph: $rph,
                roomType: self::str($response, './res:RoomTypes/res:RoomType/@RoomType', $node),
                roomTypeCode: self::str($response, './res:RoomRates/res:RoomRate/@RoomTypeCode', $node),
                bookingCode: self::str($response, './res:RoomRates/res:RoomRate/@BookingCode', $node),
                ratePlanCode: self::str($response, './res:RoomRates/res:RoomRate/@RatePlanCode', $node),
                ratePlanCategory: self::str($response, './res:RoomRates/res:RoomRate/@RatePlanCategory', $node),
                guaranteeCode: self::str($response, './res:RatePlans/res:RatePlan/res:Guarantee/@GuaranteeCode', $node),
                numberOfUnits: self::str($response, './res:RoomRates/res:RoomRate/@NumberOfUnits', $node),
                nonRefundable: $nonRefundable,
                total: $total,
                currency: self::str($response, './res:Total/@CurrencyCode', $node),
                start: self::str($response, './res:TimeSpan/@Start', $node),
                end: self::str($response, './res:TimeSpan/@End', $node),
                dailyRates: $dailyRates,
                amenities: array_values(array_unique($amenities)),
                meals: new MealsIncluded(
                    mealPlanCodes: self::str($response, './res:RatePlans/res:RatePlan/res:MealsIncluded/@MealPlanCodes', $node),
                    breakfast: self::str($response, './res:RatePlans/res:RatePlan/res:MealsIncluded/@Breakfast', $node),
                    mealPlanIndicator: self::str($response, './res:RatePlans/res:RatePlan/res:MealsIncluded/@MealPlanIndicator', $node),
                ),
                hotelCode: $hotelByRph[$rph] ?? self::str($response, './res:BasicPropertyInfo/@HotelCode', $node),
                adults: $adults,
                children: $children,
            );
        }

        return $roomStays;
    }

    /**
     * Occupancy a rate was quoted for: AgeQualifyingCode 10 counts adults,
     * 8 counts children (with their age).
     *
     * @return array{0: int, 1: array<int, array{age: string, count: string}>}
     */
    private static function parseGuestCounts(AmadeusResponse $response, \DOMNode $roomStayNode): array
    {
        $adults = 0;
        $children = [];

        foreach (self::nodes($response, './res:GuestCounts/res:GuestCount', $roomStayNode) as $guestCount) {
            $code = self::str($response, './@AgeQualifyingCode', $guestCount);
            $count = self::str($response, './@Count', $guestCount);

            if ($code === '10') {
                $adults += (int) $count;
            } elseif ($code === '8') {
                $children[] = ['age' => self::str($response, './@Age', $guestCount), 'count' => $count];
            }
        }

        return [$adults, $children];
    }

    private static function parseRoomTotal(AmadeusResponse $response, ?\DOMNode $roomStayNode): ?RoomTotal
    {
        if (! $roomStayNode) {
            return null;
        }

        $totalNode = self::nodes($response, './res:RoomRates/res:RoomRate/res:Total', $roomStayNode)->item(0);
        if (! $totalNode) {
            return null;
        }

        return new RoomTotal(
            amountBeforeTax: self::float($response, './@AmountBeforeTax', $totalNode),
            amountAfterTax: self::float($response, './@AmountAfterTax', $totalNode),
            currencyCode: self::str($response, './@CurrencyCode', $totalNode),
        );
    }

    /**
     * @return DailyRate[]
     */
    private static function parseDailyRates(AmadeusResponse $response, ?\DOMNode $roomStayNode): array
    {
        if (! $roomStayNode) {
            return [];
        }

        $rates = [];
        $rateNodes = self::nodes($response, './res:RoomRates/res:RoomRate/res:Rates/res:Rate', $roomStayNode);

        foreach ($rateNodes as $rateNode) {
            $rates[] = new DailyRate(
                effectiveDate: self::str($response, './@EffectiveDate', $rateNode),
                expireDate: self::str($response, './@ExpireDate', $rateNode),
                amountBeforeTax: self::float($response, './res:Base/@AmountBeforeTax', $rateNode),
            );
        }

        return $rates;
    }

    /**
     * @return CurrencyConversion[]
     */
    private static function parseCurrencyConversions(AmadeusResponse $response): array
    {
        $conversions = [];
        $conversionNodes = self::nodes($response, '//res:CurrencyConversions/res:CurrencyConversion');

        foreach ($conversionNodes as $node) {
            $conversions[] = new CurrencyConversion(
                sourceCurrencyCode: self::str($response, './@SourceCurrencyCode', $node),
                requestedCurrencyCode: self::str($response, './@RequestedCurrencyCode', $node),
                rateConversion: self::float($response, './@RateConversion', $node),
            );
        }

        return $conversions;
    }
}
