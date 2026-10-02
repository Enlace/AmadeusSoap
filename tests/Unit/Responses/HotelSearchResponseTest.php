<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;
use PHPUnit\Framework\TestCase;

class HotelSearchResponseTest extends TestCase
{
    protected function multiSearchXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
                <awsse:Session xmlns:awsse="http://xml.amadeus.com/2010/06/Session_v3" TransactionStatusCode="InSeries">
                    <awsse:SessionId>SESS1</awsse:SessionId>
                    <awsse:SequenceNumber>1</awsse:SequenceNumber>
                    <awsse:SecurityToken>TOK1</awsse:SecurityToken>
                </awsse:Session>
            </soapenv:Header>
            <soapenv:Body>
                <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <Warnings>
                        <Warning Tag="OK">OK</Warning>
                    </Warnings>
                    <RoomStays MoreIndicator="PAGE2">
                        <RoomStay RPH="1">
                            <RoomTypes>
                                <RoomType RoomType="STANDARD"/>
                            </RoomTypes>
                            <RatePlans>
                                <RatePlan RatePlanCode="RAC">
                                    <Guarantee GuaranteeCode="31"/>
                                    <MealsIncluded MealPlanCodes="1" Breakfast="true" MealPlanIndicator="true"/>
                                    <CancelPenalties>
                                        <CancelPenalty NonRefundable="false"/>
                                    </CancelPenalties>
                                </RatePlan>
                            </RatePlans>
                            <RoomRates>
                                <RoomRate RoomTypeCode="A1K" BookingCode="ABCDE" RatePlanCode="RAC" RatePlanCategory="GOV:RAC:N" NumberOfUnits="1">
                                    <Rates>
                                        <Rate EffectiveDate="2026-03-01" ExpireDate="2026-03-03">
                                            <Base AmountBeforeTax="1500.00"/>
                                        </Rate>
                                    </Rates>
                                    <Total AmountBeforeTax="3000.00" AmountAfterTax="3480.00" CurrencyCode="MXN"/>
                                    <Features>
                                        <Feature RoomAmenity="74"/>
                                        <Feature RoomAmenity="14"/>
                                    </Features>
                                </RoomRate>
                            </RoomRates>
                            <TimeSpan Start="2026-03-01" End="2026-03-03"/>
                            <Total CurrencyCode="MXN"/>
                        </RoomStay>
                    </RoomStays>
                    <HotelStays>
                        <HotelStay RoomStayRPH="1">
                            <BasicPropertyInfo HotelCode="MTYHLT" HotelName="HILTON MTY" ChainCode="HI" HotelSegmentCategoryCode="4">
                                <Address>
                                    <CountryName Code="MX"/>
                                </Address>
                            </BasicPropertyInfo>
                        </HotelStay>
                    </HotelStays>
                    <CurrencyConversions>
                        <CurrencyConversion SourceCurrencyCode="USD" RequestedCurrencyCode="MXN" RateConversion="17.50"/>
                    </CurrencyConversions>
                </OTA_HotelAvailRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    protected function noAvailabilityXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <Errors>
                        <Error>No availability found</Error>
                    </Errors>
                </OTA_HotelAvailRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_multi_search_response(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $this->assertTrue($response->ok);
        $this->assertFalse($response->hasErrors);
        $this->assertEmpty($response->errors);
        $this->assertCount(1, $response->hotels);
        $this->assertEquals('PAGE2', $response->moreIndicator);
    }

    public function test_it_parses_hotel_details(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $hotel = $response->hotels[0];
        $this->assertEquals('MTYHLT', $hotel->hotelCode);
        $this->assertEquals('HILTON MTY', $hotel->hotelName);
        $this->assertEquals('HI', $hotel->chainCode);
        $this->assertEquals('4', $hotel->ratingCode);
        $this->assertEquals('MX', $hotel->countryCode);
        $this->assertEquals('RAC', $hotel->ratePlanCode);
        $this->assertEquals('GOV:RAC:N', $hotel->ratePlanCategory);
        $this->assertEquals('2026-03-01', $hotel->start);
        $this->assertEquals('2026-03-03', $hotel->end);
    }

    public function test_it_parses_hotel_totals(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $hotel = $response->hotels[0];
        $this->assertNotNull($hotel->total);
        $this->assertEquals(3000.00, $hotel->total->amountBeforeTax);
        $this->assertEquals(3480.00, $hotel->total->amountAfterTax);
        $this->assertEquals('MXN', $hotel->total->currencyCode);
    }

    public function test_it_parses_daily_rates(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $hotel = $response->hotels[0];
        $this->assertCount(1, $hotel->dailyRates);
        $this->assertEquals('2026-03-01', $hotel->dailyRates[0]->effectiveDate);
        $this->assertEquals('2026-03-03', $hotel->dailyRates[0]->expireDate);
        $this->assertEquals(1500.00, $hotel->dailyRates[0]->amountBeforeTax);
    }

    public function test_it_parses_room_stays(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $this->assertCount(1, $response->roomStays);
        $roomStay = $response->roomStays[0];

        $this->assertEquals('1', $roomStay->rph);
        $this->assertEquals('STANDARD', $roomStay->roomType);
        $this->assertEquals('A1K', $roomStay->roomTypeCode);
        $this->assertEquals('ABCDE', $roomStay->bookingCode);
        $this->assertEquals('RAC', $roomStay->ratePlanCode);
        $this->assertEquals('31', $roomStay->guaranteeCode);
        $this->assertFalse($roomStay->nonRefundable);
        $this->assertEquals(['74', '14'], $roomStay->amenities);
        $this->assertEquals('true', $roomStay->meals->breakfast);
    }

    public function test_non_refundable_accepts_ota_boolean_forms_and_unknown(): void
    {
        $parse = function (string $cancelPenalty): ?bool {
            $xml = str_replace('<CancelPenalty NonRefundable="false"/>', $cancelPenalty, $this->multiSearchXml());
            $raw = new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05');

            return HotelSearchResponse::fromResponse($raw)->roomStays[0]->nonRefundable;
        };

        $this->assertTrue($parse('<CancelPenalty NonRefundable="1"/>'));
        $this->assertTrue($parse('<CancelPenalty NonRefundable="true"/>'));
        $this->assertFalse($parse('<CancelPenalty NonRefundable="0"/>'));
        $this->assertNull($parse('<CancelPenalty PolicyCode="Cancellation"/>'));
    }

    public function test_it_parses_currency_conversions(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $this->assertCount(1, $response->currencyConversions);
        $conversion = $response->currencyConversions[0];
        $this->assertEquals('USD', $conversion->sourceCurrencyCode);
        $this->assertEquals('MXN', $conversion->requestedCurrencyCode);
        $this->assertEquals(17.50, $conversion->rateConversion);
    }

    public function test_it_handles_error_response(): void
    {
        $raw = new AmadeusResponse($this->noAvailabilityXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $this->assertFalse($response->ok);
        $this->assertTrue($response->hasErrors);
        $this->assertCount(1, $response->errors);
        $this->assertInstanceOf(\Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError::class, $response->errors[0]);
        $this->assertEquals('No availability found', $response->errors[0]->message);
        $this->assertEquals('error', $response->errors[0]->type);
        $this->assertEmpty($response->hotels);
        $this->assertEmpty($response->roomStays);
    }

    public function test_it_exposes_raw_response(): void
    {
        $raw = new AmadeusResponse($this->multiSearchXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelSearchResponse::fromResponse($raw);

        $this->assertSame($raw, $response->raw);
    }

    // ---------------------------------------------------------------------
    // Multi-rate properties, against the shape a real Amadeus reply uses.
    // ---------------------------------------------------------------------

    protected function multiRateResponse(): HotelSearchResponse
    {
        $xml = file_get_contents(dirname(__DIR__, 2).'/Fixtures/responses/hotel_search_multi_rate.xml');

        return HotelSearchResponse::fromResponse(
            new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05'),
        );
    }

    public function test_it_parses_a_reply_with_several_rates_per_property(): void
    {
        $response = $this->multiRateResponse();

        $this->assertTrue($response->ok);
        $this->assertCount(2, $response->hotels);
        $this->assertCount(4, $response->roomStays);
    }

    public function test_room_stay_rph_is_split_into_a_list(): void
    {
        // Amadeus sends RoomStayRPH="0 1 2" — space-separated, not one value
        $hotel = $this->multiRateResponse()->hotels[0];

        $this->assertEquals('0 1 2', $hotel->roomStayRPH);
        $this->assertEquals(['0', '1', '2'], $hotel->roomStayRPHs);
    }

    public function test_a_multi_rate_property_still_reports_a_price(): void
    {
        // Regression: the raw "0 1 2" was compared against @RPH, matched
        // nothing, and left every multi-rate property with a null total and
        // empty plan/dates — i.e. search results with no prices.
        $hotel = $this->multiRateResponse()->hotels[0];

        $this->assertNotNull($hotel->total);
        $this->assertEquals(1666.0, $hotel->total->amountBeforeTax);
        $this->assertEquals(1982.0, $hotel->total->amountAfterTax);
        $this->assertEquals('MXN', $hotel->total->currencyCode);
        $this->assertEquals('ENF', $hotel->ratePlanCode);
        $this->assertEquals('Converted:ENF:N', $hotel->ratePlanCategory);
        $this->assertEquals('2027-05-19', $hotel->start);
        $this->assertEquals('2027-05-20', $hotel->end);
        $this->assertNotEmpty($hotel->dailyRates);
    }

    public function test_summary_fields_describe_the_first_rate(): void
    {
        // RPH 0 is ENF/1982, RPH 1 is RAC/2436, RPH 2 is COR/3712
        $hotel = $this->multiRateResponse()->hotels[0];

        $this->assertEquals('ENF', $hotel->ratePlanCode);
        $this->assertEquals(1982.0, $hotel->total->amountAfterTax);
    }

    public function test_a_single_rate_property_is_unaffected(): void
    {
        $hotel = $this->multiRateResponse()->hotels[1];

        $this->assertEquals(['3'], $hotel->roomStayRPHs);
        $this->assertEquals('BAR', $hotel->ratePlanCode);
        $this->assertEquals(1682.0, $hotel->total->amountAfterTax);
    }

    public function test_rates_can_be_paired_back_to_their_property(): void
    {
        $response = $this->multiRateResponse();

        $rates = $response->hotels[0]->roomStays($response->roomStays);

        $this->assertCount(3, $rates);
        $this->assertEquals(['0', '1', '2'], array_map(fn ($r) => $r->rph, $rates));
        $this->assertEquals(['ENF', 'RAC', 'COR'], array_map(fn ($r) => $r->ratePlanCode, $rates));
        $this->assertEquals(
            ['BCODE001', 'BCODE002', 'BCODE003'],
            array_map(fn ($r) => $r->bookingCode, $rates),
        );
    }

    public function test_pairing_does_not_leak_rates_between_properties(): void
    {
        $response = $this->multiRateResponse();

        $rates = $response->hotels[1]->roomStays($response->roomStays);

        $this->assertCount(1, $rates);
        $this->assertEquals('BCODE004', $rates[0]->bookingCode);
    }

    public function test_each_rate_carries_the_codes_pricing_requires(): void
    {
        // hotelPricing() needs rate_plan_code, booking_code and room_type_code
        $rate = $this->multiRateResponse()->roomStays[0];

        $this->assertEquals('ENF', $rate->ratePlanCode);
        $this->assertEquals('BCODE001', $rate->bookingCode);
        $this->assertEquals('N1D', $rate->roomTypeCode);
        $this->assertEquals('M1D', $rate->roomType);
        $this->assertEquals('1', $rate->numberOfUnits);
        $this->assertEquals('31', $rate->guaranteeCode);
    }

    public function test_refundability_is_read_per_rate(): void
    {
        $roomStays = $this->multiRateResponse()->roomStays;

        $this->assertFalse($roomStays[0]->nonRefundable);
        $this->assertTrue($roomStays[1]->nonRefundable);
    }

    public function test_the_session_is_readable_from_the_reply(): void
    {
        $session = $this->multiRateResponse()->raw->getSessionData();

        $this->assertNotNull($session);
        $this->assertEquals('SESSIONTEST', $session->sessionId);
        $this->assertEquals(1, $session->sequenceNumber);
        $this->assertEquals('SECURITYTOKENTEST0000', $session->securityToken);
    }

    public function test_nothing_is_parsed_without_the_ok_tagged_warning(): void
    {
        // Parsing gates on //Warnings/Warning[@Tag='OK']; without it the
        // response reports ok=false and empty collections, not partial data.
        $xml = str_replace(
            'Tag="OK"',
            'Tag="NOTOK"',
            file_get_contents(dirname(__DIR__, 2).'/Fixtures/responses/hotel_search_multi_rate.xml'),
        );

        $response = HotelSearchResponse::fromResponse(
            new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05'),
        );

        $this->assertFalse($response->ok);
        $this->assertEmpty($response->hotels);
        $this->assertEmpty($response->roomStays);
    }
}
