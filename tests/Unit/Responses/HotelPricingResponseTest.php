<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelPricingResponse;
use PHPUnit\Framework\TestCase;

class HotelPricingResponseTest extends TestCase
{
    protected function pricingXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <HotelStays>
                        <HotelStay>
                            <BasicPropertyInfo HotelCode="MTYHLT" HotelName="HILTON MTY" ChainCode="HI" HotelCityCode="MTY">
                                <Address>
                                    <CountryName Code="MX"/>
                                </Address>
                            </BasicPropertyInfo>
                        </HotelStay>
                    </HotelStays>
                    <RoomStays>
                        <RoomStay>
                            <RoomTypes>
                                <RoomType RoomType="SUPERIOR"/>
                            </RoomTypes>
                            <RatePlans>
                                <RatePlan RatePlanCode="ENF">
                                    <Commission Percent="10" StatusType="Full"/>
                                    <Guarantee GuaranteeCode="31"/>
                                    <CancelPenalties>
                                        <CancelPenalty NonRefundable="false">
                                            <AmountPercent Amount="1500.00" CurrencyCode="MXN"/>
                                            <Deadline AbsoluteDeadline="2026-02-28T18:00:00"/>
                                            <PenaltyDescription>One night penalty</PenaltyDescription>
                                        </CancelPenalty>
                                    </CancelPenalties>
                                </RatePlan>
                            </RatePlans>
                            <RoomRates>
                                <RoomRate BookingCode="XYZ" RoomTypeCode="SUP" RatePlanCode="ENF" NumberOfUnits="1">
                                    <Rates>
                                        <Rate EffectiveDate="2026-03-01" ExpireDate="2026-03-03">
                                            <Base AmountBeforeTax="1500.00"/>
                                        </Rate>
                                    </Rates>
                                    <Total AmountBeforeTax="3000.00" AmountAfterTax="3480.00" CurrencyCode="MXN">
                                        <Taxes>
                                            <Tax Code="VAT" Percent="16"/>
                                        </Taxes>
                                    </Total>
                                </RoomRate>
                            </RoomRates>
                            <TimeSpan Start="2026-03-01" End="2026-03-03"/>
                            <Total AmountBeforeTax="3000.00" AmountAfterTax="3480.00" CurrencyCode="MXN"/>
                        </RoomStay>
                    </RoomStays>
                </OTA_HotelAvailRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    protected function errorXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <Errors>
                        <Error Code="450">Invalid rate plan</Error>
                    </Errors>
                </OTA_HotelAvailRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_pricing_response(): void
    {
        $raw = new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEquals('MTYHLT', $response->hotelCode);
        $this->assertEquals('HILTON MTY', $response->hotelName);
        $this->assertEquals('HI', $response->chainCode);
        $this->assertEquals('MTY', $response->hotelCityCode);
        $this->assertEquals('MX', $response->countryCode);
        $this->assertEquals('ENF', $response->ratePlanCode);
        $this->assertEquals('10', $response->commissionPercent);
        $this->assertEquals('31', $response->guaranteeCode);
        $this->assertEquals('SUPERIOR', $response->roomType);
        $this->assertEquals('XYZ', $response->bookingCode);
        $this->assertEquals(1, $response->numberOfUnits);
        $this->assertEquals('MXN', $response->currency);
    }

    public function test_it_parses_totals(): void
    {
        $raw = new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        // XPath matches both RoomRate/Total and RoomStay/Total (2 nodes)
        // The controller uses max/min on these to get overall and per-room totals
        $this->assertGreaterThanOrEqual(1, count($response->totals));
        $this->assertEquals(3000.00, $response->totals[0]->amountBeforeTax);
        $this->assertEquals(3480.00, $response->totals[0]->amountAfterTax);
    }

    public function test_it_parses_taxes(): void
    {
        $raw = new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        $this->assertCount(1, $response->taxes);
        $this->assertEquals('VAT', $response->taxes[0]->code);
        $this->assertEquals(16.0, $response->taxes[0]->percent);
    }

    public function test_it_parses_daily_rates(): void
    {
        $raw = new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        $this->assertCount(1, $response->dailyRates);
        $this->assertEquals(1500.00, $response->dailyRates[0]->amountBeforeTax);
    }

    public function test_it_parses_cancel_penalties(): void
    {
        $raw = new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        $this->assertCount(1, $response->cancelPenalties);
        $penalty = $response->cancelPenalties[0];
        $this->assertFalse($penalty->nonRefundable);
        $this->assertEquals(1500.00, $penalty->amount);
        $this->assertEquals('MXN', $penalty->currencyCode);
        $this->assertEquals('2026-02-28T18:00:00', $penalty->absoluteDeadline);
        $this->assertEquals(['One night penalty'], $penalty->descriptions);
    }

    public function test_non_refundable_penalties_accept_both_ota_boolean_forms(): void
    {
        foreach (['true' => true, '1' => true, 'false' => false, '0' => false] as $value => $expected) {
            $xml = str_replace('<CancelPenalty NonRefundable="false">', "<CancelPenalty NonRefundable=\"{$value}\">", $this->pricingXml());
            $raw = new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05');

            $this->assertSame($expected, HotelPricingResponse::fromResponse($raw)->cancelPenalties[0]->nonRefundable, "NonRefundable=\"{$value}\"");
        }
    }

    public function test_accepted_cards_are_those_of_the_priced_rate_plan(): void
    {
        $cards = '<GuaranteesAccepted>'
            .'<GuaranteeAccepted><PaymentCard CardCode="VI"/></GuaranteeAccepted>'
            .'<GuaranteeAccepted><PaymentCard CardCode="mc"/></GuaranteeAccepted>'
            .'<GuaranteeAccepted><PaymentCard CardCode="VI"/></GuaranteeAccepted>'
            .'</GuaranteesAccepted>';
        $xml = str_replace(
            '<Guarantee GuaranteeCode="31"/>',
            "<Guarantee GuaranteeCode=\"31\">{$cards}</Guarantee>",
            $this->pricingXml(),
        );
        // Another rate plan in the reply: its cards are not the priced rate's
        $xml = str_replace(
            '</RatePlans>',
            '<RatePlan RatePlanCode="OTH"><Guarantee GuaranteeCode="31"><GuaranteesAccepted><GuaranteeAccepted><PaymentCard CardCode="AX"/></GuaranteeAccepted></GuaranteesAccepted></Guarantee></RatePlan></RatePlans>',
            $xml,
        );

        $response = HotelPricingResponse::fromResponse(new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05'));

        $this->assertSame(['VI', 'MC'], $response->acceptedCardCodes);
    }

    public function test_a_priced_rate_listing_no_cards_has_none(): void
    {
        $response = HotelPricingResponse::fromResponse(new AmadeusResponse($this->pricingXml(), 'http://www.opentravel.org/OTA/2003/05'));

        $this->assertSame([], $response->acceptedCardCodes);
    }

    public function test_cards_are_unknown_when_no_rate_plan_matches_the_booking_code(): void
    {
        $xml = str_replace('<RatePlan RatePlanCode="ENF">', '<RatePlan RatePlanCode="NOPE">', $this->pricingXml());

        $response = HotelPricingResponse::fromResponse(new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05'));

        $this->assertNull($response->acceptedCardCodes);
    }

    public function test_it_parses_the_rate_category_and_currency_conversions(): void
    {
        $xml = str_replace(
            ['<RoomRate BookingCode="XYZ"', '<RoomStays>'],
            [
                '<RoomRate RatePlanCategory="Converted:BAR:P" BookingCode="XYZ"',
                '<CurrencyConversions><CurrencyConversion SourceCurrencyCode="USD" RequestedCurrencyCode="MXN" RateConversion="17.5133"/></CurrencyConversions><RoomStays>',
            ],
            $this->pricingXml(),
        );

        $response = HotelPricingResponse::fromResponse(new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05'));

        $this->assertSame('Converted:BAR:P', $response->ratePlanCategory);
        $this->assertCount(1, $response->currencyConversions);
        $this->assertSame('USD', $response->currencyConversions[0]->sourceCurrencyCode);
        $this->assertSame('MXN', $response->currencyConversions[0]->requestedCurrencyCode);
        $this->assertSame(17.5133, $response->currencyConversions[0]->rateConversion);
    }

    public function test_it_parses_errors(): void
    {
        $raw = new AmadeusResponse($this->errorXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelPricingResponse::fromResponse($raw);

        $this->assertTrue($response->hasErrors);
        $this->assertCount(1, $response->errors);
        $this->assertEquals('450', $response->errors[0]->code);
        $this->assertEquals('Invalid rate plan', $response->errors[0]->message);
    }
}
