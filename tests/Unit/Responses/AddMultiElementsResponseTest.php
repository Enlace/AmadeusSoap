<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use PHPUnit\Framework\TestCase;

class AddMultiElementsResponseTest extends TestCase
{
    protected function createResponseXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRADD_17_1_1A">
                    <travellerInfo>
                        <elementManagementPassenger>
                            <reference>
                                <qualifier>PT</qualifier>
                                <number>1</number>
                            </reference>
                        </elementManagementPassenger>
                        <passengerData>
                            <travellerInformation>
                                <traveller>
                                    <surname>GARCIA</surname>
                                </traveller>
                                <passenger>
                                    <firstName>JUAN</firstName>
                                    <type>ADT</type>
                                </passenger>
                            </travellerInformation>
                        </passengerData>
                    </travellerInfo>
                    <dataElementsIndiv>
                        <elementManagementData>
                            <segmentName>AP</segmentName>
                            <reference>
                                <qualifier>OT</qualifier>
                                <number>5</number>
                            </reference>
                        </elementManagementData>
                    </dataElementsIndiv>
                </PNR_Reply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    protected function endResponseXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRADD_17_1_1A">
                    <pnrHeader>
                        <reservationInfo>
                            <reservation>
                                <controlNumber>ABC123</controlNumber>
                            </reservation>
                        </reservationInfo>
                    </pnrHeader>
                    <travellerInfo>
                        <elementManagementPassenger>
                            <reference>
                                <qualifier>PT</qualifier>
                                <number>1</number>
                            </reference>
                        </elementManagementPassenger>
                        <passengerData>
                            <travellerInformation>
                                <traveller>
                                    <surname>GARCIA</surname>
                                </traveller>
                                <passenger>
                                    <firstName>JUAN</firstName>
                                    <type>ADT</type>
                                </passenger>
                            </travellerInformation>
                        </passengerData>
                    </travellerInfo>
                    <originDestinationDetails>
                        <itineraryInfo>
                            <elementManagementItinerary>
                                <segmentName>HHL</segmentName>
                                <reference>
                                    <qualifier>ST</qualifier>
                                    <number>2</number>
                                </reference>
                            </elementManagementItinerary>
                            <hotelReservationInfo>
                                <cancelOrConfirmNbr>
                                    <reservation>
                                        <controlNumber>CONF456</controlNumber>
                                    </reservation>
                                </cancelOrConfirmNbr>
                                <hotelPropertyInfo>
                                    <hotelReference>
                                        <chainCode>HI</chainCode>
                                        <cityCode>MTY</cityCode>
                                        <hotelCode>HLT</hotelCode>
                                    </hotelReference>
                                </hotelPropertyInfo>
                            </hotelReservationInfo>
                            <referenceForSegment>
                                <reference>
                                    <qualifier>HOP</qualifier>
                                    <number>1</number>
                                </reference>
                            </referenceForSegment>
                            <hotelProduct>
                                <negotiated>ENF</negotiated>
                            </hotelProduct>
                        </itineraryInfo>
                    </originDestinationDetails>
                </PNR_Reply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    protected function errorResponseXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRADD_17_1_1A">
                    <generalErrorInfo>
                        <messageErrorInformation>
                            <errorDetail>
                                <qualifier>EC</qualifier>
                                <code>1234</code>
                            </errorDetail>
                        </messageErrorInformation>
                        <messageErrorText>
                            <text>PNR creation failed</text>
                        </messageErrorText>
                    </generalErrorInfo>
                </PNR_Reply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_create_response(): void
    {
        $raw = new AmadeusResponse($this->createResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEquals('5', $response->travelAgentRef);
        $this->assertCount(1, $response->travelers);
        $this->assertEquals('JUAN', $response->travelers[0]->firstName);
        $this->assertEquals('GARCIA', $response->travelers[0]->surname);
        $this->assertEquals('1', $response->travelers[0]->referenceNumber);
    }

    public function test_it_finds_traveler_by_name(): void
    {
        $raw = new AmadeusResponse($this->createResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $traveler = $response->findTravelerByName('JUAN', 'GARCIA');
        $this->assertNotNull($traveler);
        $this->assertEquals('1', $traveler->referenceNumber);

        $this->assertNull($response->findTravelerByName('PEDRO', 'LOPEZ'));
    }

    public function test_it_parses_end_response_with_pnr(): void
    {
        $raw = new AmadeusResponse($this->endResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $this->assertFalse($response->hasErrors);
        $this->assertEquals('ABC123', $response->pnrNumber);
        $this->assertEquals('ENF', $response->ratePlanCode);
        $this->assertCount(1, $response->segments);
    }

    public function test_it_parses_segments(): void
    {
        $raw = new AmadeusResponse($this->endResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $segment = $response->segments[0];
        $this->assertEquals('2', $segment->segmentNumber);
        $this->assertEquals('CONF456', $segment->confirmationNumber);
        $this->assertEquals('1', $segment->passengerReference);
        $this->assertEquals('HI', $segment->chainCode);
        $this->assertEquals('MTY', $segment->cityCode);
        $this->assertEquals('HIMTYHLT', $segment->hotelCode);
    }

    public function test_it_detects_segment_deletion(): void
    {
        $raw = new AmadeusResponse($this->endResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $this->assertFalse($response->isSegmentDeleted('2'));
        $this->assertTrue($response->isSegmentDeleted('99'));
    }

    public function test_it_detects_errors(): void
    {
        $raw = new AmadeusResponse($this->errorResponseXml(), 'http://xml.amadeus.com/PNRADD_17_1_1A');
        $response = AddMultiElementsResponse::fromResponse($raw);

        $this->assertTrue($response->hasErrors);
        $this->assertCount(1, $response->errors);
        $this->assertEquals('PNR creation failed', $response->errors[0]->message);
        $this->assertEquals('EC', $response->errors[0]->code);
        $this->assertEquals('error', $response->errors[0]->type);
    }
}
