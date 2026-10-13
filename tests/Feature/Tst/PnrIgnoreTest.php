<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Tests\TestCase;

/**
 * Ignoring the PNR (IG) after a refused sell, against what TST accepted
 * (scripts/tst-chain.php --ignore-check): Amadeus drops the names the attempt
 * added, and the session stays open with its availability context, so another
 * rate can be priced and sold without duplicating them.
 */
class PnrIgnoreTest extends TestCase
{
    public function test_ignore_sends_the_request_amadeus_accepted_and_keeps_the_session(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create', 'pnr-ignore', 'hotel-pricing');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $room = $amadeus->hotelSearch('single', ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []])->roomStays[1];
        $amadeus->addMultiElements('create', ['surname' => 'TEST', 'name' => 'TESTER', 'type' => 'ADT']);
        $ignore = $amadeus->addMultiElements('ignore');
        $amadeus->hotelPricing($room);

        [$search, , $ignoreXml, $pricing] = array_column($client->requests, 'xml');

        $this->assertSoapBodyMatchesFixture('pnr-ignore', $ignoreXml);
        $this->assertFalse($ignore->hasErrors);
        $this->assertSame([], $ignore->travelers);

        // The IG does not end the session: pricing goes on in series, not a new one
        $this->assertSame('Start', $this->soapHeader($search, 'Session', 'TransactionStatusCode'));
        $this->assertSame('InSeries', $this->soapHeader($ignoreXml, 'Session', 'TransactionStatusCode'));
        $this->assertSame('InSeries', $this->soapHeader($pricing, 'Session', 'TransactionStatusCode'));
        $this->assertTrue($amadeus->session()->hasSession());
    }
}
