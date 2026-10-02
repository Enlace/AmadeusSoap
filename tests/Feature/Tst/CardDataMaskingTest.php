<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Data\PaymentCard;
use Aldogtz\AmadeusSoap\Data\Traveler;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Facades\Log;

/**
 * The card goes to Amadeus as given, but nothing the package hands out after
 * the call — last request, logs, exceptions — carries the number or the CVC.
 */
class CardDataMaskingTest extends TestCase
{
    protected const CARD_NUMBER = '378282246310005';

    protected const SECURITY_CODE = '4321';

    protected function sell(AmadeusSoap $amadeus): void
    {
        $room = $amadeus->hotelSearch('single', [
            'hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => [],
        ])->roomStays[1];
        $pnr = $amadeus->addMultiElements('create', new Traveler('TRAVELER', 'TEST'));

        $amadeus->hotelSell($room, $pnr, new PaymentCard('AX', self::CARD_NUMBER, self::SECURITY_CODE, '1230', 'TEST TRAVELER'));
    }

    protected function assertMasked(?string $xml): void
    {
        $this->assertNotNull($xml);
        $this->assertStringNotContainsString(self::CARD_NUMBER, $xml);
        $this->assertStringContainsString('XXXXXXXXXXX0005', $xml);
        // The element, not the bare digits: a message ID may contain them
        $this->assertMatchesRegularExpression('#securityId>XXXX</#', $xml);
    }

    public function test_the_last_request_is_masked_but_amadeus_gets_the_card(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->sell($amadeus);

        $this->assertStringContainsString(self::CARD_NUMBER, $client->requests[2]['xml']);
        $this->assertMatchesRegularExpression('#securityId>'.self::SECURITY_CODE.'</#', $client->requests[2]['xml']);
        $this->assertMasked($amadeus->getLastRequest());
    }

    public function test_a_refused_sell_carries_the_masked_request(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create');
        $client->queueResponse(<<<'XML'
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <soap:Fault>
                        <faultcode>soap:Client</faultcode>
                        <faultstring>12|Presentation|card refused</faultstring>
                    </soap:Fault>
                </soap:Body>
            </soap:Envelope>
            XML);
        $amadeus = $this->app->make(AmadeusSoap::class);

        try {
            $this->sell($amadeus);
            $this->fail('Expected SoapFaultException');
        } catch (SoapFaultException $e) {
            $this->assertMasked($e->getLastRequest());
        }
    }

    public function test_the_logged_request_is_masked(): void
    {
        config(['amadeus-soap.logging.enabled' => true, 'amadeus-soap.logging.operations' => ['Hotel_Sell']]);
        $this->fakeAmadeus('hotel-search-single', 'pnr-create', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $logged = [];
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('log')->andReturnUsing(function (string $level, string $message, array $context = []) use (&$logged) {
            $logged[$message] = $context['xml'] ?? null;
        });

        $this->sell($amadeus);

        $this->assertMasked($logged['Amadeus SOAP Request [Hotel_Sell]'] ?? null);
    }
}
