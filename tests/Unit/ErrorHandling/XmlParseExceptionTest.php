<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\ErrorHandling;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Exceptions\XmlParseException;
use PHPUnit\Framework\TestCase;

class XmlParseExceptionTest extends TestCase
{
    public function test_empty_response_throws_xml_parse_exception(): void
    {
        $this->expectException(XmlParseException::class);
        $this->expectExceptionMessage('empty response');

        new AmadeusResponse('', 'http://xml.amadeus.com/PNRADD_17_1_1A');
    }

    public function test_whitespace_only_response_throws_xml_parse_exception(): void
    {
        $this->expectException(XmlParseException::class);
        $this->expectExceptionMessage('empty response');

        new AmadeusResponse('   ', 'http://xml.amadeus.com/PNRADD_17_1_1A');
    }

    public function test_malformed_xml_throws_xml_parse_exception(): void
    {
        $this->expectException(XmlParseException::class);
        $this->expectExceptionMessage('Failed to parse');

        new AmadeusResponse('<invalid><xml>', 'http://xml.amadeus.com/PNRADD_17_1_1A');
    }

    public function test_xml_parse_exception_exposes_raw_xml(): void
    {
        $badXml = '<invalid><xml>';

        try {
            new AmadeusResponse($badXml, 'http://xml.amadeus.com/PNRADD_17_1_1A');
            $this->fail('Expected XmlParseException');
        } catch (XmlParseException $e) {
            $this->assertEquals($badXml, $e->getRawXml());
            $this->assertNotEmpty($e->getXmlErrors());
        }
    }

    public function test_valid_xml_parses_successfully(): void
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRADD_17_1_1A"/>
            </soapenv:Body>
        </soapenv:Envelope>';

        $response = new AmadeusResponse($xml, 'http://xml.amadeus.com/PNRADD_17_1_1A');

        $this->assertNotNull($response->xpath());
    }

    public function test_empty_response_factory(): void
    {
        $exception = XmlParseException::emptyResponse();

        $this->assertStringContainsString('empty response', $exception->getMessage());
        $this->assertNull($exception->getRawXml());
        $this->assertEmpty($exception->getXmlErrors());
    }
}
