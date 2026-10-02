<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use RuntimeException;

/**
 * usingSession() runs a flow (a queued job, an inspection) on its own
 * session instead of the authenticated user's, and gives the key back.
 */
class ScopedSessionTest extends TestCase
{
    protected function searchParams(): array
    {
        return ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []];
    }

    protected function faultXml(string $faultString): string
    {
        return <<<XML
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <soap:Fault>
                        <faultcode>soap:Client</faultcode>
                        <faultstring>{$faultString}</faultstring>
                    </soap:Fault>
                </soap:Body>
            </soap:Envelope>
            XML;
    }

    public function test_the_flow_stores_its_session_under_its_own_key(): void
    {
        $this->fakeAmadeus('hotel-search-single');
        $amadeus = $this->app->make(AmadeusSoap::class);
        $store = $this->app->make(SessionStore::class);

        $result = $amadeus->usingSession('approval:7', function (AmadeusSoap $amadeus) {
            $this->assertSame('approval:7', $amadeus->session()->getSessionKey());

            return $amadeus->hotelSearch('single', $this->searchParams());
        });

        $this->assertTrue($result->ok);
        $this->assertTrue($store->has('approval:7'));
        // Nobody is authenticated: the default key is 'system'
        $this->assertFalse($store->has('system'));
        $this->assertSame('system', $amadeus->session()->getSessionKey());
    }

    public function test_the_key_is_given_back_when_the_flow_throws(): void
    {
        $amadeus = $this->app->make(AmadeusSoap::class);

        try {
            $amadeus->usingSession('approval:7', fn () => throw new RuntimeException('boom'));
            $this->fail('Expected the exception to propagate');
        } catch (RuntimeException $e) {
            $this->assertSame('boom', $e->getMessage());
        }

        $this->assertSame('system', $amadeus->session()->getSessionKey());
    }

    public function test_nested_flows_give_back_the_outer_key(): void
    {
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->usingSession('outer', function (AmadeusSoap $amadeus) {
            $amadeus->usingSession('inner', fn () => $this->assertSame('inner', $amadeus->session()->getSessionKey()));

            $this->assertSame('outer', $amadeus->session()->getSessionKey());
        });

        $this->assertSame('system', $amadeus->session()->getSessionKey());
    }

    public function test_the_flow_can_sign_its_session_out_when_it_ends(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'signout');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->usingSession('approval:7', fn (AmadeusSoap $amadeus) => $amadeus->hotelSearch('single', $this->searchParams()), signOut: true);

        $this->assertCount(2, $client->requests);
        $this->assertStringContainsString('<Security_SignOut', $client->requests[1]['xml']);
        $this->assertFalse($this->app->make(SessionStore::class)->has('approval:7'));
    }

    public function test_the_session_is_signed_out_when_the_flow_throws(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'signout');
        $amadeus = $this->app->make(AmadeusSoap::class);

        try {
            $amadeus->usingSession('approval:7', function (AmadeusSoap $amadeus) {
                $amadeus->hotelSearch('single', $this->searchParams());

                throw new RuntimeException('the sell failed');
            }, signOut: true);
            $this->fail('Expected the exception to propagate');
        } catch (RuntimeException $e) {
            $this->assertSame('the sell failed', $e->getMessage());
        }

        $this->assertStringContainsString('<Security_SignOut', $client->requests[1]['xml']);
        $this->assertFalse($this->app->make(SessionStore::class)->has('approval:7'));
    }

    public function test_a_failed_sign_out_is_reported_not_thrown(): void
    {
        $reported = $this->recordReportedExceptions();
        $client = $this->fakeAmadeus('hotel-search-single');
        $client->queueResponse($this->faultXml('95|Session|Inactive conversation'));
        $amadeus = $this->app->make(AmadeusSoap::class);

        $result = $amadeus->usingSession('approval:7', fn (AmadeusSoap $amadeus) => $amadeus->hotelSearch('single', $this->searchParams()), signOut: true);

        $this->assertTrue($result->ok);
        $this->assertReported($reported, SoapFaultException::class);
        $this->assertFalse($this->app->make(SessionStore::class)->has('approval:7'));
    }

    public function test_nothing_is_signed_out_when_the_flow_opened_no_session(): void
    {
        $client = $this->fakeAmadeus('hotel-descriptive-info');
        $amadeus = $this->app->make(AmadeusSoap::class);

        // Hotel_DescriptiveInfo is stateless
        $amadeus->usingSession('inspector:1', fn (AmadeusSoap $amadeus) => $amadeus->hotelDescriptiveInfo('YZMTY045'), signOut: true);

        $this->assertCount(1, $client->requests);
    }
}
