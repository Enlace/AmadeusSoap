<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Headers\BodyBuilder;
use Aldogtz\AmadeusSoap\Operations\HotelDescriptiveInfo;
use Aldogtz\AmadeusSoap\Operations\HotelPricing;
use Aldogtz\AmadeusSoap\Operations\HotelSearch;
use PHPUnit\Framework\TestCase;

/**
 * The OTA-schema operations carry their message-level values as attributes of
 * the request root, not as child elements.
 *
 * Emitting them as elements produced a well-formed request that Amadeus TST
 * rejected with " 11|Session|". The operation tests only inspected the arrays,
 * never the serialised XML, so nothing caught it — these assertions look at
 * the rendered body.
 */
class OtaRootAttributesTest extends TestCase
{
    protected function render(array $body, string $rootElement): string
    {
        return (string) BodyBuilder::build($body, $rootElement)->enc_value;
    }

    protected function searchXml(): string
    {
        $operation = new HotelSearch(HotelSearchParams::fromArray([
            'hotel_city_code' => 'MTY',
            'start' => '2027-05-19',
            'end' => '2027-05-20',
        ]));

        return $this->render($operation->build(), 'OTA_HotelAvailRQ');
    }

    public function test_search_puts_message_values_on_the_root_as_attributes(): void
    {
        $xml = $this->searchXml();

        foreach ([
            'EchoToken="MultiSingle"',
            'Version="4.000"',
            'PrimaryLangID="EN"',
            'SummaryOnly="true"',
            'AvailRatesOnly="true"',
            'RateRangeOnly="true"',
            'SearchCacheLevel="Live"',
            'RateDetailsInd="true"',
            'RequestedCurrency="MXN"',
            'MaxResponses="96"',
            'ExactMatchOnly="true"',
        ] as $attribute) {
            $this->assertStringContainsString($attribute, $xml);
        }
    }

    public function test_search_does_not_emit_them_as_child_elements(): void
    {
        $xml = $this->searchXml();

        foreach (['EchoToken', 'Version', 'PrimaryLangID', 'SummaryOnly', 'SearchCacheLevel',
            'RateDetailsInd', 'RequestedCurrency', 'MaxResponses', 'ExactMatchOnly'] as $name) {
            $this->assertStringNotContainsString("<{$name}>", $xml);
        }
    }

    public function test_the_search_root_keeps_its_only_child(): void
    {
        $xml = $this->searchXml();

        $this->assertStringContainsString('<AvailRequestSegments>', $xml);
        $this->assertStringStartsWith('<OTA_HotelAvailRQ ', $xml);
    }

    public function test_sort_order_becomes_a_root_attribute_when_given(): void
    {
        $operation = new HotelSearch(HotelSearchParams::fromArray([
            'hotel_city_code' => 'MTY',
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'sort_order' => 'RA',
        ]));

        $xml = $this->render($operation->build(), 'OTA_HotelAvailRQ');

        $this->assertStringContainsString('SortOrder="RA"', $xml);
        $this->assertStringNotContainsString('<SortOrder>', $xml);
    }

    public function test_pricing_puts_message_values_on_the_root(): void
    {
        $operation = new HotelPricing(HotelPricingParams::fromArray([
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'hotel_code' => 'CITST001',
            'rate_plan_code' => 'ENF',
            'booking_code' => 'BCODE001',
            'room_type_code' => 'N1D',
            'quantity' => '1',
            'guest_count' => '1',
        ]));

        $xml = $this->render($operation->build(), 'OTA_HotelAvailRQ');

        $this->assertStringContainsString('EchoToken="Pricing"', $xml);
        $this->assertStringContainsString('Version="4.000"', $xml);
        $this->assertStringContainsString('SummaryOnly="false"', $xml);
        $this->assertStringContainsString('RequestedCurrency="MXN"', $xml);
        $this->assertStringNotContainsString('<EchoToken>', $xml);
        $this->assertStringNotContainsString('<SummaryOnly>', $xml);
    }

    public function test_descriptive_info_puts_message_values_on_the_root(): void
    {
        $operation = new HotelDescriptiveInfo(HotelDescriptiveInfoParams::fromArray([
            'hotelCode' => 'CITST001',
        ]));

        $xml = $this->render($operation->build(), 'OTA_HotelDescriptiveInfoRQ');

        $this->assertStringContainsString('EchoToken="withParsing"', $xml);
        $this->assertStringContainsString('Version="6.001"', $xml);
        $this->assertStringContainsString('PrimaryLangID="en"', $xml);
        $this->assertStringNotContainsString('<EchoToken>', $xml);
        $this->assertStringContainsString('<HotelDescriptiveInfos>', $xml);
    }

    public function test_the_rendered_bodies_are_well_formed_xml(): void
    {
        foreach ([$this->searchXml()] as $xml) {
            $document = new \DOMDocument;
            $this->assertTrue($document->loadXML($xml), 'body should parse');
        }
    }
}
