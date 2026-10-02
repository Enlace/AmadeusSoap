<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Data;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use PHPUnit\Framework\TestCase;

class AmadeusResponseTest extends TestCase
{
    protected function sampleXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
                <awsse:Session xmlns:awsse="http://xml.amadeus.com/2010/06/Session_v3" TransactionStatusCode="InSeries">
                    <awsse:SessionId>SESS123</awsse:SessionId>
                    <awsse:SequenceNumber>2</awsse:SequenceNumber>
                    <awsse:SecurityToken>TOKEN456</awsse:SecurityToken>
                </awsse:Session>
            </soapenv:Header>
            <soapenv:Body>
                <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <Warnings>
                        <Warning Tag="OK">OK</Warning>
                    </Warnings>
                    <HotelStays>
                        <HotelStay RoomStayRPH="1">
                            <BasicPropertyInfo HotelCode="MTYHLT" HotelName="HILTON MTY"/>
                        </HotelStay>
                    </HotelStays>
                </OTA_HotelAvailRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_can_evaluate_xpath(): void
    {
        $response = new AmadeusResponse(
            $this->sampleXml(),
            'http://www.opentravel.org/OTA/2003/05'
        );

        $hotelCode = $response->evaluate('string(//res:BasicPropertyInfo/@HotelCode)');
        $this->assertEquals('MTYHLT', $hotelCode);
    }

    public function test_it_detects_ok_warning(): void
    {
        $response = new AmadeusResponse(
            $this->sampleXml(),
            'http://www.opentravel.org/OTA/2003/05'
        );

        $this->assertTrue($response->hasOkWarning());
    }

    public function test_it_extracts_session_data(): void
    {
        $response = new AmadeusResponse(
            $this->sampleXml(),
            'http://www.opentravel.org/OTA/2003/05'
        );

        $session = $response->getSessionData();
        $this->assertNotNull($session);
        $this->assertEquals('SESS123', $session->sessionId);
        $this->assertEquals(2, $session->sequenceNumber);
        $this->assertEquals('TOKEN456', $session->securityToken);
    }

    public function test_it_returns_raw_xml(): void
    {
        $xml = $this->sampleXml();
        $response = new AmadeusResponse($xml, 'http://www.opentravel.org/OTA/2003/05');

        $this->assertNotEmpty($response->getRawXml());
    }
}
