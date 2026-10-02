<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Carbon;

/**
 * Full booking flow against sanitized Amadeus TST traffic.
 *
 * Responses are real TST replies; request bodies are compared with the
 * requests Amadeus TST accepted. See tests/Fixtures/sanitize-tst-captures.php.
 */
class BookingFlowTest extends TestCase
{
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    protected function searchParams(): array
    {
        return [
            'hotel_code' => 'YZMTY045',
            'start' => '2026-08-30',
            'end' => '2026-08-31',
            'rate_code' => [],
        ];
    }

    protected function pricingParams(): array
    {
        return [
            'hotel_code' => 'YZMTY045',
            'start' => '2026-08-30',
            'end' => '2026-08-31',
            'rate_plan_code' => '57J',
            'booking_code' => '1KN57JU',
            'room_type_code' => '*1K',
            'quantity' => 1,
            'guest_count' => 1,
        ];
    }

    protected function sellParams(array $overrides = []): array
    {
        return array_merge([
            'travelAgentRef' => '1',
            'chainCode' => 'YZ',
            'cityCode' => 'MTY',
            'hotelCode' => 'YZMTY045',
            'bookingCode' => '1KN57JU',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
            'paymentType' => '1',
            'vendorCode' => 'AX',
            'cardNumber' => '378282246310005',
            'securityId' => '0000',
            'expiryDate' => '1230',
            'surname' => 'TRAVELER',
            'firstName' => 'TEST',
        ], $overrides);
    }

    public function test_search_pricing_and_pnr_send_the_requests_amadeus_accepted(): void
    {
        Carbon::setTestNow('2026-07-31 17:23:00');
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-pricing', 'pnr-create');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $amadeus->hotelPricing($this->pricingParams());
        $amadeus->addMultiElements('create', ['surname' => 'TRAVELER', 'name' => 'TEST', 'type' => 'ADT']);

        $this->assertSoapBodyMatchesFixture('hotel-search-single', $client->requests[0]['xml']);
        $this->assertSoapBodyMatchesFixture('hotel-pricing', $client->requests[1]['xml']);
        $this->assertSoapBodyMatchesFixture('pnr-create', $client->requests[2]['xml']);
    }

    public function test_sell_and_sign_out_send_the_requests_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-sell', 'signout');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $amadeus->hotelSell($this->sellParams());
        $amadeus->signOut();

        $this->assertSoapBodyMatchesFixture('hotel-sell', $client->requests[1]['xml']);
        $this->assertSoapBodyMatchesFixture('signout', $client->requests[2]['xml']);
    }

    public function test_the_session_started_by_search_is_continued_until_sign_out(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-pricing', 'pnr-create', 'signout');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $searchSession = $amadeus->session()->getSessionData();

        $amadeus->hotelPricing($this->pricingParams());
        $amadeus->addMultiElements('create', ['surname' => 'TRAVELER', 'name' => 'TEST', 'type' => 'ADT']);
        $amadeus->signOut();

        [$search, $pricing, $pnr, $signOut] = array_column($client->requests, 'xml');

        // The search starts a session and authenticates
        $this->assertSame('Start', $this->soapHeader($search, 'Session', 'TransactionStatusCode'));
        $this->assertNotNull($this->soapHeader($search, 'UsernameToken'));
        $this->assertSame('TEST01', $this->soapHeader($search, 'UserID', 'PseudoCityCode'));

        // Pricing continues the session the search reply opened
        $this->assertNotNull($searchSession);
        $this->assertSame('InSeries', $this->soapHeader($pricing, 'Session', 'TransactionStatusCode'));
        $this->assertSame($searchSession->sessionId, $this->soapHeader($pricing, 'SessionId'));
        $this->assertSame((string) ($searchSession->sequenceNumber + 1), $this->soapHeader($pricing, 'SequenceNumber'));
        $this->assertNull($this->soapHeader($pricing, 'UsernameToken'));

        foreach ([$pnr, $signOut] as $request) {
            $this->assertSame('InSeries', $this->soapHeader($request, 'Session', 'TransactionStatusCode'));
        }

        $this->assertFalse($amadeus->session()->hasSession());
    }

    public function test_it_parses_the_real_search_and_pricing_replies(): void
    {
        $this->fakeAmadeus('hotel-search-single', 'hotel-pricing');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $search = $amadeus->hotelSearch('single', $this->searchParams());
        $pricing = $amadeus->hotelPricing($this->pricingParams());

        $this->assertTrue($search->ok);
        $this->assertCount(1, $search->hotels);
        $this->assertSame('YZMTY045', $search->hotels[0]->hotelCode);
        $this->assertCount(8, $search->roomStays);
        $this->assertSame(['57J', 'M85'], array_values(array_unique(array_map(fn ($r) => $r->ratePlanCode, $search->roomStays))));

        $this->assertFalse($pricing->hasErrors);
        $this->assertSame('YZMTY045', $pricing->hotelCode);
        $this->assertSame('1KN57JU', $pricing->bookingCode);
        $this->assertSame('57J', $pricing->ratePlanCode);
        $this->assertSame('MXN', $pricing->currency);
    }

    public function test_a_failed_sell_is_reported_as_an_error(): void
    {
        // Real TST reply: errorGroup with code CTL and no description, 0 rooms booked
        $this->fakeAmadeus('hotel-search-single', 'hotel-sell-ctl-error');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $sell = $amadeus->hotelSell($this->sellParams());

        $this->assertTrue($sell->hasErrors);
        $this->assertSame('CTL', $sell->errors[0]->code);
        $this->assertNull($sell->confirmationNumber);
    }

    public function test_it_completes_a_booking_from_sell_to_sign_out(): void
    {
        // PNR_Retrieve starts a new session: the booking session is signed out first
        $this->fakeAmadeus('hotel-search-single', 'hotel-sell', 'pnr-end', 'signout', 'pnr-retrieve', 'hotel-complete-reservation-details', 'signout');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());

        $sell = $amadeus->hotelSell($this->sellParams([
            'chainCode' => 'HI',
            'hotelCode' => 'HIMTY8D2',
            'bookingCode' => 'STN57JU',
        ]));
        $this->assertFalse($sell->hasErrors);
        $this->assertSame('10000001', $sell->confirmationNumber);
        $this->assertSame('STN57JU', $sell->roomResults[0]->bookingCode);
        $this->assertSame('HIMTY8D2', $sell->roomResults[0]->hotelCode);

        $end = $amadeus->addMultiElements('end');
        $this->assertFalse($end->hasErrors);
        $this->assertSame('TST002', $end->pnrNumber);
        $this->assertSame('57J', $end->ratePlanCode);
        $this->assertSame('10000001', $end->segments[0]->confirmationNumber);
        $this->assertSame('HIMTY8D2', $end->segments[0]->hotelCode);

        $retrieve = $amadeus->pnrRetrieve(['pnrNumber' => 'TST002']);
        $this->assertSame('TST002', $retrieve->pnrNumber);
        $this->assertCount(1, $retrieve->segments);

        $details = $amadeus->hotelCompleteReservationDetails([
            'pnrNumber' => 'TST002',
            'segmentNumber' => $end->segments[0]->segmentNumber,
        ]);
        $this->assertFalse($details->hasErrors);
        $this->assertSame('MXN', $details->currency);
        $this->assertSame(5140.0, $details->totalAmountWithTax);

        $signOut = $amadeus->signOut();
        $this->assertFalse($amadeus->session()->hasSession());
        $this->assertNotNull($signOut);
    }
}
