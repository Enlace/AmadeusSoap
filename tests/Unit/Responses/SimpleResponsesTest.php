<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSellResponse;
use Aldogtz\AmadeusSoap\Data\Responses\PnrCancelResponse;
use Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse;
use PHPUnit\Framework\TestCase;

class SimpleResponsesTest extends TestCase
{
    public function test_hotel_sell_detects_errors(): void
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <Hotel_SellReply xmlns="http://xml.amadeus.com/HBKRCR_07_1_1A">
                    <errorGroup>
                        <errorWarningCode>
                            <errorDetails>
                                <errorCode>1234</errorCode>
                            </errorDetails>
                        </errorWarningCode>
                        <errorWarningDescription>
                            <freeText>Sell failed</freeText>
                        </errorWarningDescription>
                    </errorGroup>
                </Hotel_SellReply>
            </soapenv:Body>
        </soapenv:Envelope>';

        $raw = new AmadeusResponse($xml, 'http://xml.amadeus.com/HBKRCR_07_1_1A');
        $response = HotelSellResponse::fromResponse($raw);

        $this->assertTrue($response->hasErrors);
        $this->assertCount(1, $response->errors);
        $this->assertEquals('Sell failed', $response->errors[0]->message);
        $this->assertEquals('1234', $response->errors[0]->code);
    }

    public function test_hotel_sell_success(): void
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <Hotel_SellReply xmlns="http://xml.amadeus.com/HBKRCR_07_1_1A">
                    <hotelReservationInfo>
                        <controlNumber>CONF789</controlNumber>
                    </hotelReservationInfo>
                </Hotel_SellReply>
            </soapenv:Body>
        </soapenv:Envelope>';

        $raw = new AmadeusResponse($xml, 'http://xml.amadeus.com/HBKRCR_07_1_1A');
        $response = HotelSellResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEmpty($response->errors);
    }

    public function test_pnr_cancel_exposes_raw(): void
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRACC_17_1_1A"/>
            </soapenv:Body>
        </soapenv:Envelope>';

        $raw = new AmadeusResponse($xml, 'http://xml.amadeus.com/PNRACC_17_1_1A');
        $response = PnrCancelResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEmpty($response->errors);
        $this->assertSame($raw, $response->raw);
    }

    public function test_sign_out_exposes_raw(): void
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <Security_SignOutReply xmlns="http://xml.amadeus.com/VLSSOQ_04_1_1A"/>
            </soapenv:Body>
        </soapenv:Envelope>';

        $raw = new AmadeusResponse($xml, 'http://xml.amadeus.com/VLSSOQ_04_1_1A');
        $response = SignOutResponse::fromResponse($raw);

        $this->assertSame($raw, $response->raw);
        $this->assertSame('http://xml.amadeus.com/VLSSOQ_04_1_1A', SignOutResponse::fromXml($xml)->raw->getResponseNamespace());
    }
}
