<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CancelPenalty;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CurrencyConversion;
use Aldogtz\AmadeusSoap\Data\Responses\Values\DailyRate;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RoomTotal;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Tax;

final class HotelPricingResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  RoomTotal[]  $totals
     * @param  Tax[]  $taxes
     * @param  DailyRate[]  $dailyRates
     * @param  CancelPenalty[]  $cancelPenalties
     * @param  CurrencyConversion[]  $currencyConversions
     * @param  string[]|null  $acceptedCardCodes  Cards the priced rate's guarantee accepts
     *                                            (VI, MC, AX…): [] when the rate lists none,
     *                                            null when no rate plan matches the priced
     *                                            booking code
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly string $hotelCode,
        public readonly string $hotelName,
        public readonly string $chainCode,
        public readonly string $hotelCityCode,
        public readonly string $countryCode,
        public readonly string $ratePlanCode,
        public readonly string $commissionPercent,
        public readonly string $commissionStatusType,
        public readonly string $guaranteeCode,
        public readonly string $roomType,
        public readonly string $bookingCode,
        public readonly int $numberOfUnits,
        public readonly string $currency,
        public readonly string $start,
        public readonly string $end,
        public readonly array $totals,
        public readonly array $taxes,
        public readonly array $dailyRates,
        public readonly array $cancelPenalties,
        public readonly AmadeusResponse $raw,
        public readonly string $ratePlanCategory = '',
        public readonly array $currencyConversions = [],
        public readonly ?array $acceptedCardCodes = null,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = self::parseOtaErrors($response);
        $hasErrors = count($errors) > 0;
        $bookingCode = self::str($response, '//res:RoomStay/res:RoomRates/res:RoomRate/@BookingCode');

        return new self(
            hasErrors: $hasErrors,
            errors: $errors,
            hotelCode: self::str($response, '//res:HotelStay/res:BasicPropertyInfo/@HotelCode'),
            hotelName: self::str($response, '//res:HotelStay/res:BasicPropertyInfo/@HotelName'),
            chainCode: self::str($response, '//res:BasicPropertyInfo/@ChainCode'),
            hotelCityCode: self::str($response, '//res:HotelStay/res:BasicPropertyInfo/@HotelCityCode'),
            countryCode: self::str($response, '//res:BasicPropertyInfo/res:Address/res:CountryName/@Code'),
            ratePlanCode: self::str($response, '//res:RoomStay/res:RatePlans/res:RatePlan/@RatePlanCode'),
            commissionPercent: self::str($response, '//res:RoomStays/res:RoomStay/res:RatePlans/res:RatePlan/res:Commission/@Percent'),
            commissionStatusType: self::str($response, '//res:RoomStays/res:RoomStay/res:RatePlans/res:RatePlan/res:Commission/@StatusType'),
            guaranteeCode: self::str($response, '//res:RoomStay/res:RatePlans/res:RatePlan/res:Guarantee/@GuaranteeCode'),
            roomType: self::str($response, '//res:RoomStay/res:RoomTypes/res:RoomType/@RoomType'),
            bookingCode: $bookingCode,
            numberOfUnits: self::int($response, '//res:RoomStay/res:RoomRates/res:RoomRate/@NumberOfUnits'),
            currency: self::str($response, '//res:RoomStay/res:Total/@CurrencyCode'),
            start: self::str($response, '//res:RoomStay/res:TimeSpan/@Start'),
            end: self::str($response, '//res:RoomStay/res:TimeSpan/@End'),
            totals: self::parseTotals($response),
            taxes: self::parseTaxes($response),
            dailyRates: self::parseDailyRates($response),
            cancelPenalties: self::cancelPenaltiesAt($response, '//res:CancelPenalties/res:CancelPenalty'),
            raw: $response,
            ratePlanCategory: self::str($response, '//res:RoomStay/res:RoomRates/res:RoomRate/@RatePlanCategory'),
            currencyConversions: self::currencyConversionsAt($response, '//res:CurrencyConversions/res:CurrencyConversion'),
            acceptedCardCodes: self::parseAcceptedCardCodes($response, $bookingCode),
        );
    }

    /**
     * Cards accepted by the rate plan of the priced booking code: the
     * RatePlan whose RatePlanCode is the one on the RoomRate carrying that
     * booking code.
     *
     * @return string[]|null null when no rate plan matches
     */
    private static function parseAcceptedCardCodes(AmadeusResponse $response, string $bookingCode): ?array
    {
        if ($bookingCode === '') {
            return null;
        }

        $codes = [];
        $matched = false;
        $booking = self::xpathLiteral($bookingCode);

        foreach (self::nodes($response, '//res:RoomStay') as $roomStay) {
            $ratePlanCodes = [];
            foreach (self::nodes($response, "./res:RoomRates/res:RoomRate[@BookingCode = {$booking}]/@RatePlanCode", $roomStay) as $node) {
                $ratePlanCodes[] = self::xpathLiteral((string) $node->nodeValue);
            }

            foreach ($ratePlanCodes as $ratePlanCode) {
                $ratePlans = self::nodes($response, "./res:RatePlans/res:RatePlan[@RatePlanCode = {$ratePlanCode}]", $roomStay);

                foreach ($ratePlans as $ratePlan) {
                    $matched = true;
                    $codes = array_merge($codes, self::cardCodesAt(
                        $response,
                        './res:Guarantee/res:GuaranteesAccepted/res:GuaranteeAccepted/res:PaymentCard/@CardCode',
                        $ratePlan,
                    ));
                }
            }
        }

        return $matched ? array_values(array_unique($codes)) : null;
    }

    /**
     * @return RoomTotal[]
     */
    private static function parseTotals(AmadeusResponse $response): array
    {
        $totals = [];
        $totalNodes = self::nodes($response, '//res:Total[not(ancestor::res:Rate)]');

        foreach ($totalNodes as $node) {
            $totals[] = new RoomTotal(
                amountBeforeTax: self::float($response, './@AmountBeforeTax', $node),
                amountAfterTax: self::float($response, './@AmountAfterTax', $node),
                currencyCode: self::str($response, './@CurrencyCode', $node),
            );
        }

        return $totals;
    }

    /**
     * @return Tax[]
     */
    private static function parseTaxes(AmadeusResponse $response): array
    {
        // The first Tax of each code plus every code 27, with a Percent or an
        // Amount: the selection BookingV2 priced with
        return self::taxesAt($response, "//res:RoomStays/res:RoomStay/res:RoomRates/res:RoomRate/res:Total/res:Taxes/res:Tax[(not(@Code = preceding::res:Tax/@Code) or @Code = '27') and (@Percent or @Amount)]");
    }

    /**
     * @return DailyRate[]
     */
    private static function parseDailyRates(AmadeusResponse $response): array
    {
        $rates = [];
        $rateNodes = self::nodes($response, '//res:RoomStay/res:RoomRates/res:RoomRate/res:Rates/res:Rate[count(./res:Base) > 0]');

        foreach ($rateNodes as $node) {
            $rates[] = new DailyRate(
                effectiveDate: self::str($response, './@EffectiveDate', $node),
                expireDate: self::str($response, './@ExpireDate', $node),
                amountBeforeTax: self::float($response, './res:Base/@AmountBeforeTax', $node),
            );
        }

        return $rates;
    }
}
