<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Tests\TestCase;

/**
 * Single-hotel searches and PNR_Retrieve always start a new Amadeus session.
 * The stored one must be signed out first, not left open until it times out.
 */
class SessionReplacementTest extends TestCase
{
    protected function searchParams(): array
    {
        return ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []];
    }

    public function test_the_replaced_session_is_signed_out_before_the_new_one_starts(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'signout', 'hotel-search-single');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $first = $amadeus->session()->getSessionData();
        $amadeus->hotelSearch('single', $this->searchParams());

        [$search, $signOut, $nextSearch] = array_column($client->requests, 'xml');

        $this->assertSame('Start', $this->soapHeader($search, 'Session', 'TransactionStatusCode'));

        $this->assertStringContainsString('<Security_SignOut', $signOut);
        $this->assertSame('InSeries', $this->soapHeader($signOut, 'Session', 'TransactionStatusCode'));
        $this->assertSame($first->sessionId, $this->soapHeader($signOut, 'SessionId'));

        $this->assertSame('Start', $this->soapHeader($nextSearch, 'Session', 'TransactionStatusCode'));
        $this->assertTrue($amadeus->session()->hasSession());
    }

    public function test_a_failed_sign_out_does_not_fail_the_new_session(): void
    {
        $reported = $this->recordReportedExceptions();
        $client = $this->fakeAmadeus('hotel-search-single');
        // The stored session already expired on Amadeus
        $client->queueResponse(<<<'XML'
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <soap:Fault>
                        <faultcode>soap:Client</faultcode>
                        <faultstring>95|Session|Inactive conversation</faultstring>
                    </soap:Fault>
                </soap:Body>
            </soap:Envelope>
            XML);
        $client->queueResponse($this->tstFixture('responses/hotel-search-single.xml'));
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $response = $amadeus->hotelSearch('single', $this->searchParams());

        $this->assertTrue($response->ok);
        $this->assertCount(3, $client->requests);
        $this->assertTrue($amadeus->session()->hasSession());
        $this->assertReported($reported, SoapFaultException::class);
    }

    public function test_replaced_sessions_are_left_alone_when_disabled(): void
    {
        config(['amadeus-soap.session.sign_out_replaced' => false]);
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-search-single');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', $this->searchParams());
        $amadeus->hotelSearch('single', $this->searchParams());

        $this->assertCount(2, $client->requests);
    }
}
