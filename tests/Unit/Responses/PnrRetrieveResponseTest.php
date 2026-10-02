<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse;
use PHPUnit\Framework\TestCase;

class PnrRetrieveResponseTest extends TestCase
{
    protected function pnrRetrieveXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRACC_17_1_1A">
                    <pnrHeader>
                        <reservationInfo>
                            <reservation>
                                <controlNumber>XYZ789</controlNumber>
                            </reservation>
                        </reservationInfo>
                    </pnrHeader>
                    <originDestinationDetails>
                        <itineraryInfo>
                            <elementManagementItinerary>
                                <segmentName>HHL</segmentName>
                                <reference>
                                    <qualifier>ST</qualifier>
                                    <number>2</number>
                                </reference>
                            </elementManagementItinerary>
                        </itineraryInfo>
                        <itineraryInfo>
                            <elementManagementItinerary>
                                <segmentName>HHL</segmentName>
                                <reference>
                                    <qualifier>ST</qualifier>
                                    <number>3</number>
                                </reference>
                            </elementManagementItinerary>
                        </itineraryInfo>
                        <itineraryInfo>
                            <elementManagementItinerary>
                                <segmentName>AIR</segmentName>
                                <reference>
                                    <qualifier>ST</qualifier>
                                    <number>1</number>
                                </reference>
                            </elementManagementItinerary>
                        </itineraryInfo>
                    </originDestinationDetails>
                </PNR_Reply>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_pnr_number(): void
    {
        $raw = new AmadeusResponse($this->pnrRetrieveXml(), 'http://xml.amadeus.com/PNRACC_17_1_1A');
        $response = PnrRetrieveResponse::fromResponse($raw);

        $this->assertEquals('XYZ789', $response->pnrNumber);
    }

    public function test_it_parses_only_hotel_segments(): void
    {
        $raw = new AmadeusResponse($this->pnrRetrieveXml(), 'http://xml.amadeus.com/PNRACC_17_1_1A');
        $response = PnrRetrieveResponse::fromResponse($raw);

        // Should only find HHL segments, not AIR
        $this->assertCount(2, $response->segments);
        $this->assertEquals('2', $response->segments[0]->segmentNumber);
        $this->assertEquals('3', $response->segments[1]->segmentNumber);
    }
}
