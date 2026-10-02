<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;

final class HotelCompleteReservationDetailsResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  ReservationTax[]  $taxes
     * @param  string[]  $cancellationDescriptions
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly string $countryCode,
        public readonly string $currency,
        public readonly float $totalAmount,
        public readonly float $totalAmountWithTax,
        public readonly array $taxes,
        public readonly array $cancellationDescriptions,
        public readonly AmadeusResponse $raw,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = [];
        $errorInfoNodes = self::nodes($response, '//res:errorInformation');
        foreach ($errorInfoNodes as $node) {
            $text = self::str($response, './res:errorText/res:text', $node);
            $code = self::str($response, './res:errorDetails/res:errorCode', $node);
            $errors[] = new AmadeusError(
                message: $text ?: 'Unknown error',
                code: $code,
                type: 'error',
            );
        }
        $hasErrors = count($errors) > 0;

        $countryCode = self::str($response, '//res:countryStateInformation/res:countryCode');
        $currency = self::str($response, '//res:Hotel_CompleteReservationDetailsReply/res:hotelSalesRequirementsSection/res:hotelSalesRequCategorySection/res:rateInformationSection/res:rateAmountInformation/res:tariffInfo/res:currency');
        $totalAmount = self::float($response, '//res:Hotel_CompleteReservationDetailsReply/res:hotelSalesRequirementsSection/res:hotelSalesRequCategorySection/res:rateInformationSection/res:rateAmountInformation/res:tariffInfo/res:totalAmount');
        $totalAmountWithTax = self::float($response, "//res:Hotel_CompleteReservationDetailsReply/res:hotelSalesRequirementsSection/res:hotelSalesRequCategorySection/res:totalAmountInformation/res:monetaryDetails[./res:typeQualifier/text() = '712']/res:amount");

        $taxes = self::parseTaxes($response);
        $cancellationDescriptions = self::parseCancellationDescriptions($response);

        return new self(
            hasErrors: $hasErrors,
            errors: $errors,
            countryCode: $countryCode,
            currency: $currency,
            totalAmount: $totalAmount,
            totalAmountWithTax: $totalAmountWithTax,
            taxes: $taxes,
            cancellationDescriptions: $cancellationDescriptions,
            raw: $response,
        );
    }

    /**
     * @return ReservationTax[]
     */
    private static function parseTaxes(AmadeusResponse $response): array
    {
        $taxes = [];
        $taxNodes = self::nodes($response, '//res:taxSection/res:taxFeeInformation');

        foreach ($taxNodes as $node) {
            $includedInAmount = self::bool($response, "count(./res:includedInAmount[./text() = 'I']) > 0", $node);
            $amount = self::float($response, './res:amount', $node);
            $percentage = self::float($response, './res:percentage', $node);
            $timeUnit = self::str($response, './res:timeUnit', $node);

            // Date range for per-day taxes
            $beginDate = self::dateAt($response, '../res:taxFeeValidity/res:beginDateTime', $node);
            $endDate = self::dateAt($response, '../res:taxFeeValidity/res:endDateTime', $node);

            $taxes[] = new ReservationTax(
                amount: $amount,
                percentage: $percentage,
                timeUnit: $timeUnit,
                includedInAmount: $includedInAmount,
                beginDate: $beginDate,
                endDate: $endDate,
            );
        }

        return $taxes;
    }

    /**
     * @return string[]
     */
    private static function parseCancellationDescriptions(AmadeusResponse $response): array
    {
        $descriptions = [];
        $cxlNode = self::nodes($response, "//res:hotelSalesRequCategorySection[./res:pricingCategory/res:itemDescriptionType/text() = 'CXL']")->item(0);

        if (! $cxlNode) {
            return $descriptions;
        }

        $textNodes = self::nodes($response, './res:infoMsgAndCancelPolicies/res:freeText', $cxlNode);
        foreach ($textNodes as $textNode) {
            $descriptions[] = $textNode->textContent;
        }

        return $descriptions;
    }
}
