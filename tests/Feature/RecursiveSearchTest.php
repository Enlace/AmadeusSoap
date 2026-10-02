<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Logging\SoapLogger;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Testing\AmadeusFake;
use Aldogtz\AmadeusSoap\Tests\Doubles\FakeTransport;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;

/**
 * Covers recursiveHotelSearch(), which walks Amadeus' MoreIndicator token.
 *
 * It used to recurse only when the response was NOT ok, so a successful search
 * with more pages returned the first page and stopped; and because it returned
 * the recursive call's result directly, any page it did fetch replaced the
 * earlier ones instead of adding to them.
 */
class RecursiveSearchTest extends TestCase
{
    protected FakeTransport $transport;

    protected function amadeus(FakeTransport $transport): AmadeusSoap
    {
        return new AmadeusSoap(
            wsdlManager: new WsdlManager(AmadeusFake::wsdlDirectory()),
            sessionManager: new SessionManager(
                store: new ArraySessionStore,
                keyResolver: fn () => 'recursive-test',
                statelessOperations: ['Hotel_DescriptiveInfo'],
            ),
            transport: $transport,
            logger: new SoapLogger(enabled: false),
            config: [],
        );
    }

    /**
     * Build a search reply with the given hotel/RPH numbering and an optional
     * MoreIndicator, reusing the multi-rate fixture's element shapes.
     */
    protected function page(string $hotelCode, string $rph, ?string $moreIndicator): string
    {
        $more = $moreIndicator === null ? '' : ' MoreIndicator="'.$moreIndicator.'"';

        return <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                               xmlns:awsse="http://xml.amadeus.com/2010/06/Session_v3">
                <SOAP-ENV:Header>
                    <awsse:Session TransactionStatusCode="InSeries">
                        <awsse:SessionId>SESSIONTEST</awsse:SessionId>
                        <awsse:SequenceNumber>1</awsse:SequenceNumber>
                        <awsse:SecurityToken>SECURITYTOKENTEST0000</awsse:SecurityToken>
                    </awsse:Session>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                        <Success/>
                        <Warnings>
                            <Warning Type="3" Tag="OK"/>
                        </Warnings>
                        <HotelStays>
                            <HotelStay RoomStayRPH="{$rph}">
                                <BasicPropertyInfo ChainCode="CI" HotelCode="{$hotelCode}"
                                                   HotelName="HOTEL {$hotelCode}" HotelSegmentCategoryCode="4">
                                    <Address><CountryName Code="MX"/></Address>
                                </BasicPropertyInfo>
                            </HotelStay>
                        </HotelStays>
                        <RoomStays{$more}>
                            <RoomStay RPH="{$rph}">
                                <RoomTypes><RoomType RoomType="M1D" RoomTypeCode="N1D"/></RoomTypes>
                                <RatePlans>
                                    <RatePlan RatePlanCode="RAC">
                                        <Guarantee GuaranteeCode="31"/>
                                        <MealsIncluded Breakfast="0"/>
                                    </RatePlan>
                                </RatePlans>
                                <RoomRates>
                                    <RoomRate BookingCode="BC{$hotelCode}" RoomTypeCode="N1D"
                                              NumberOfUnits="1" RatePlanCode="RAC" RatePlanCategory="Converted:RAC:N">
                                        <Total AmountBeforeTax="1000" AmountAfterTax="1160" CurrencyCode="MXN"/>
                                    </RoomRate>
                                </RoomRates>
                                <TimeSpan Start="2027-05-19" End="2027-05-20"/>
                                <Total AmountBeforeTax="1000" AmountAfterTax="1160" CurrencyCode="MXN"/>
                            </RoomStay>
                        </RoomStays>
                    </OTA_HotelAvailRS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            XML;
    }

    protected function params(): array
    {
        return [
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'hotel_city_code' => 'MTY',
        ];
    }

    public function test_a_single_page_search_makes_one_call(): void
    {
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', null));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(1, $transport->calls);
        $this->assertCount(1, $response->hotels);
        $this->assertNull($response->moreIndicator);
    }

    public function test_it_follows_the_more_indicator_across_pages(): void
    {
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'TOKEN2'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL2', '0', 'TOKEN3'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL3', '0', null));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(3, $transport->calls);
        $this->assertNull($response->moreIndicator);
    }

    public function test_results_from_every_page_are_kept(): void
    {
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'TOKEN2'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL2', '0', 'TOKEN3'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL3', '0', null));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(3, $response->hotels);
        $this->assertEquals(
            ['HOTEL1', 'HOTEL2', 'HOTEL3'],
            array_map(fn ($h) => $h->hotelCode, $response->hotels),
        );
        $this->assertCount(3, $response->roomStays);
    }

    public function test_the_echo_token_is_sent_on_follow_up_calls(): void
    {
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'TOKEN2'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL2', '0', null));

        $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertStringNotContainsString('TOKEN2', $transport->calls[0]['body']);
        $this->assertStringContainsString('TOKEN2', $transport->calls[1]['body']);
    }

    public function test_rphs_reused_across_pages_stay_paired_with_their_property(): void
    {
        // Every page numbers its rates from 0, so a naive merge would make
        // each hotel resolve to the first page's rate.
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'TOKEN2'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL2', '0', null));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(2, $response->hotels);

        $first = $response->hotels[0]->roomStays($response->roomStays);
        $second = $response->hotels[1]->roomStays($response->roomStays);

        $this->assertCount(1, $first);
        $this->assertCount(1, $second);
        $this->assertEquals('BCHOTEL1', $first[0]->bookingCode);
        $this->assertEquals('BCHOTEL2', $second[0]->bookingCode);
    }

    public function test_it_stops_at_the_page_cap(): void
    {
        // A server that always reports more pages must not loop forever
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'ALWAYS'));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params(), maxPages: 3);

        // First page plus one follow-up: the repeated token stops the walk
        $this->assertCount(2, $transport->calls);
        $this->assertCount(2, $response->hotels);
    }

    public function test_a_repeated_token_ends_the_walk(): void
    {
        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'SAME'))
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL2', '1', 'SAME'));

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(2, $transport->calls);
        $this->assertCount(2, $response->hotels);
    }

    public function test_an_empty_follow_up_page_does_not_discard_earlier_results(): void
    {
        $empty = <<<'XML'
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Body>
                    <OTA_HotelAvailRS xmlns="http://www.opentravel.org/OTA/2003/05">
                        <Errors><Error>No more results</Error></Errors>
                    </OTA_HotelAvailRS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            XML;

        $transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', $this->page('HOTEL1', '0', 'TOKEN2'))
            ->reply('Hotel_MultiSingleAvailability', $empty);

        $response = $this->amadeus($transport)->recursiveHotelSearch($this->params());

        $this->assertCount(1, $response->hotels);
        $this->assertEquals('HOTEL1', $response->hotels[0]->hotelCode);
        $this->assertFalse($response->hasErrors);
    }
}
