<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelCompleteReservationDetailsResponse;
use PHPUnit\Framework\TestCase;

class HotelCompleteReservationDetailsResponseTest extends TestCase
{
    protected function reservationDetailsXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <Hotel_CompleteReservationDetailsReply xmlns="http://xml.amadeus.com/HRTLSS_07_3_1A">
                    <generalInformation>
                        <countryStateInformation>
                            <countryCode>MX</countryCode>
                        </countryStateInformation>
                    </generalInformation>
                    <hotelSalesRequirementsSection>
                        <hotelSalesRequCategorySection>
                            <pricingCategory>
                                <itemDescriptionType>RTE</itemDescriptionType>
                            </pricingCategory>
                            <rateInformationSection>
                                <rateAmountInformation>
                                    <tariffInfo>
                                        <currency>MXN</currency>
                                        <totalAmount>3000.00</totalAmount>
                                    </tariffInfo>
                                </rateAmountInformation>
                            </rateInformationSection>
                            <totalAmountInformation>
                                <monetaryDetails>
                                    <typeQualifier>712</typeQualifier>
                                    <amount>3480.00</amount>
                                </monetaryDetails>
                            </totalAmountInformation>
                            <taxSection>
                                <taxFeeInformation>
                                    <amount>480.00</amount>
                                    <percentage>16</percentage>
                                    <timeUnit>ST</timeUnit>
                                    <includedInAmount>I</includedInAmount>
                                </taxFeeInformation>
                                <taxFeeInformation>
                                    <amount>50.00</amount>
                                    <percentage>0</percentage>
                                    <timeUnit>DY</timeUnit>
                                </taxFeeInformation>
                                <taxFeeValidity>
                                    <beginDateTime>
                                        <year>2026</year>
                                        <month>03</month>
                                        <day>01</day>
                                    </beginDateTime>
                                    <endDateTime>
                                        <year>2026</year>
                                        <month>03</month>
                                        <day>03</day>
                                    </endDateTime>
                                </taxFeeValidity>
                            </taxSection>
                        </hotelSalesRequCategorySection>
                        <hotelSalesRequCategorySection>
                            <pricingCategory>
                                <itemDescriptionType>CXL</itemDescriptionType>
                            </pricingCategory>
                            <infoMsgAndCancelPolicies>
                                <freeText>Free cancellation until 48 hours before check-in.</freeText>
                            </infoMsgAndCancelPolicies>
                            <infoMsgAndCancelPolicies>
                                <freeText>One night penalty after deadline.</freeText>
                            </infoMsgAndCancelPolicies>
                        </hotelSalesRequCategorySection>
                    </hotelSalesRequirementsSection>
                </Hotel_CompleteReservationDetailsReply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    protected function errorXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <Hotel_CompleteReservationDetailsReply xmlns="http://xml.amadeus.com/HRTLSS_07_3_1A">
                    <errorInformation>
                        <errorDetails>
                            <errorCode>123</errorCode>
                        </errorDetails>
                        <errorText>
                            <text>Reservation not found</text>
                        </errorText>
                    </errorInformation>
                </Hotel_CompleteReservationDetailsReply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_reservation_details(): void
    {
        $raw = new AmadeusResponse($this->reservationDetailsXml(), 'http://xml.amadeus.com/HRTLSS_07_3_1A');
        $response = HotelCompleteReservationDetailsResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEquals('MX', $response->countryCode);
        $this->assertEquals('MXN', $response->currency);
        $this->assertEquals(3000.00, $response->totalAmount);
        $this->assertEquals(3480.00, $response->totalAmountWithTax);
    }

    public function test_it_parses_taxes(): void
    {
        $raw = new AmadeusResponse($this->reservationDetailsXml(), 'http://xml.amadeus.com/HRTLSS_07_3_1A');
        $response = HotelCompleteReservationDetailsResponse::fromResponse($raw);

        $this->assertCount(2, $response->taxes);

        $tax1 = $response->taxes[0];
        $this->assertEquals(480.00, $tax1->amount);
        $this->assertEquals(16.0, $tax1->percentage);
        $this->assertEquals('ST', $tax1->timeUnit);
        $this->assertTrue($tax1->includedInAmount);

        $tax2 = $response->taxes[1];
        $this->assertEquals(50.00, $tax2->amount);
        $this->assertEquals('DY', $tax2->timeUnit);
        $this->assertFalse($tax2->includedInAmount);
    }

    public function test_it_parses_cancellation_descriptions(): void
    {
        $raw = new AmadeusResponse($this->reservationDetailsXml(), 'http://xml.amadeus.com/HRTLSS_07_3_1A');
        $response = HotelCompleteReservationDetailsResponse::fromResponse($raw);

        $this->assertCount(2, $response->cancellationDescriptions);
        $this->assertStringContainsString('Free cancellation', $response->cancellationDescriptions[0]);
        $this->assertStringContainsString('One night penalty', $response->cancellationDescriptions[1]);
    }

    public function test_it_detects_errors(): void
    {
        $raw = new AmadeusResponse($this->errorXml(), 'http://xml.amadeus.com/HRTLSS_07_3_1A');
        $response = HotelCompleteReservationDetailsResponse::fromResponse($raw);

        $this->assertTrue($response->hasErrors);
        $this->assertCount(1, $response->errors);
        $this->assertEquals('Reservation not found', $response->errors[0]->message);
        $this->assertEquals('123', $response->errors[0]->code);
    }
}
