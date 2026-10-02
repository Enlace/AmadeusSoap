<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Facades\Amadeus;
use Aldogtz\AmadeusSoap\Facades\AmadeusSoapFacade;
use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use RuntimeException;

/**
 * Amadeus::fake() as an application's test suite uses it: its own config
 * (Redis sessions, real WSDL directory, credentials or not) and fixture files.
 */
class AmadeusFakeTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // An application's settings, none of which a fake may touch
        $app['config']->set('amadeus-soap.wsdl_path', '/nonexistent/wsdl');
        $app['config']->set('amadeus-soap.session.driver', 'redis');
        $app['config']->set('amadeus-soap.username', null);
        $app['config']->set('amadeus-soap.password', null);
        $app['config']->set('amadeus-soap.office_id', null);
    }

    protected function fixture(string $name): string
    {
        return __DIR__."/../Fixtures/tst/responses/{$name}.xml";
    }

    protected function searchParams(): array
    {
        return ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []];
    }

    public function test_calls_are_answered_from_the_queue(): void
    {
        $fake = Amadeus::fake()->pushFile($this->fixture('hotel-search-single'), $this->fixture('hotel-pricing'));

        $room = Amadeus::hotelSearch('single', $this->searchParams())->roomStays[1];
        $pricing = Amadeus::hotelPricing($room);

        $this->assertSame('1KN57JU', $pricing->bookingCode);
        $this->assertInstanceOf(ArraySessionStore::class, $this->app->make(SessionStore::class));

        $fake->assertSentCount(2)
            ->assertSent('Hotel_MultiSingleAvailability')
            ->assertSent('Hotel_EnhancedPricing', fn (string $xml) => str_contains($xml, '1KN57JU'))
            ->assertNotSent('Hotel_Sell')
            ->assertNoPendingReplies();

        $this->assertCount(1, $fake->sent('Hotel_EnhancedPricing'));
    }

    public function test_replies_can_be_queued_as_xml(): void
    {
        $fake = Amadeus::fake([file_get_contents($this->fixture('hotel-search-single'))]);

        $this->assertTrue(Amadeus::hotelSearch('single', $this->searchParams())->ok);
        $this->assertSame(0, $fake->pendingReplies());
    }

    public function test_an_unexpected_call_fails_loudly(): void
    {
        Amadeus::fake()->assertNothingSent();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unexpected Amadeus call (no reply queued): Hotel_MultiSingleAvailability');

        Amadeus::hotelSearch('single', $this->searchParams());
    }

    public function test_a_queued_fault_is_thrown_as_amadeus_would(): void
    {
        Amadeus::fake()->pushFault('12|Presentation|card refused');

        try {
            Amadeus::hotelSearch('single', $this->searchParams());
            $this->fail('Expected SoapFaultException');
        } catch (SoapFaultException $e) {
            $this->assertStringContainsString('card refused', $e->getMessage());
        }
    }

    public function test_the_dev_main_facade_name_still_resolves_and_mocks(): void
    {
        AmadeusSoapFacade::fake();

        $this->assertSame(Amadeus::getFacadeRoot(), AmadeusSoapFacade::getFacadeRoot());
        $this->assertInstanceOf(AmadeusSoap::class, AmadeusSoapFacade::getFacadeRoot());

        $reply = HotelSearchResponse::fromXml(file_get_contents($this->fixture('hotel-search-single')));
        AmadeusSoapFacade::shouldReceive('hotelSearch')->once()->andReturn($reply);

        $this->assertSame($reply, Amadeus::hotelSearch('single', $this->searchParams()));
    }

    public function test_a_reply_fixture_parses_without_knowing_its_namespace(): void
    {
        $search = HotelSearchResponse::fromXml(file_get_contents($this->fixture('hotel-search-single')));
        $this->assertTrue($search->ok);
        $this->assertSame('1KN57JU', $search->roomStays[1]->bookingCode);

        // A bare reply element, without the SOAP envelope
        $bare = AmadeusResponse::fromXml('<PNR_Reply xmlns="http://xml.amadeus.com/PNRACC_21_1_1A"><pnrHeader/></PNR_Reply>');
        $this->assertSame('http://xml.amadeus.com/PNRACC_21_1_1A', $bare->getResponseNamespace());
        $this->assertSame(1.0, $bare->evaluate('count(//res:pnrHeader)'));
    }
}
