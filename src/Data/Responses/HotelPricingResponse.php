<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;
use Aldogtz\AmadeusSoap\Data\Responses\Values\CancelPenalty;
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
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = self::parseOtaErrors($response);
        $hasErrors = count($errors) > 0;

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
            bookingCode: self::str($response, '//res:RoomStay/res:RoomRates/res:RoomRate/@BookingCode'),
            numberOfUnits: self::int($response, '//res:RoomStay/res:RoomRates/res:RoomRate/@NumberOfUnits'),
            currency: self::str($response, '//res:RoomStay/res:Total/@CurrencyCode'),
            start: self::str($response, '//res:RoomStay/res:TimeSpan/@Start'),
            end: self::str($response, '//res:RoomStay/res:TimeSpan/@End'),
            totals: self::parseTotals($response),
            taxes: self::parseTaxes($response),
            dailyRates: self::parseDailyRates($response),
            cancelPenalties: self::parseCancelPenalties($response),
            raw: $response,
        );
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
        $taxes = [];
        $taxNodes = self::nodes($response, "//res:RoomStays/res:RoomStay/res:RoomRates/res:RoomRate/res:Total/res:Taxes/res:Tax[(not(@Code = preceding::res:Tax/@Code) or @Code = '27') and (@Percent or @Amount)]");

        foreach ($taxNodes as $node) {
            $taxes[] = new Tax(
                code: self::str($response, './@Code', $node) ?: null,
                percent: self::float($response, './@Percent', $node) ?: null,
                amount: self::float($response, './@Amount', $node) ?: null,
                currencyCode: self::str($response, './@CurrencyCode', $node) ?: null,
                chargeUnit: self::str($response, './@ChargeUnit', $node) ?: null,
            );
        }

        return $taxes;
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

    /**
     * @return CancelPenalty[]
     */
    private static function parseCancelPenalties(AmadeusResponse $response): array
    {
        $penalties = [];
        $penaltyNodes = self::nodes($response, '//res:CancelPenalties/res:CancelPenalty');

        foreach ($penaltyNodes as $node) {
            $descriptions = [];
            $descNodes = self::nodes($response, './res:PenaltyDescription', $node);
            foreach ($descNodes as $descNode) {
                $descriptions[] = $descNode->nodeValue;
            }

            $penalties[] = new CancelPenalty(
                // OTA booleans arrive as "true"/"false" or "1"/"0"
                nonRefundable: self::otaBoolean($response, './@NonRefundable', $node) === true,
                amount: self::float($response, './res:AmountPercent/@Amount', $node),
                currencyCode: self::str($response, './res:AmountPercent/@CurrencyCode', $node),
                absoluteDeadline: self::str($response, './res:Deadline/@AbsoluteDeadline', $node) ?: null,
                descriptions: $descriptions,
            );
        }

        return $penalties;
    }
}
