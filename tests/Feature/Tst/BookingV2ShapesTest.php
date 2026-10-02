<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Support\Carbon;

/**
 * The params BookingV2 builds in production (AmadeusController::store),
 * against the requests TST accepted for them: MCMEXSFM, one room with a
 * principal guest and a companion.
 */
class BookingV2ShapesTest extends TestCase
{
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    protected function openSession(AmadeusSoap $amadeus): void
    {
        $amadeus->hotelSearch('single', [
            'hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => [],
        ]);
    }

    public function test_every_occupant_with_the_retention_date_and_a_loyalty_remark(): void
    {
        // The retention segment is capped at today + 361 days
        Carbon::setTestNow('2026-10-02 23:53:36');
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->openSession($amadeus);
        $occupant = ['surname' => 'TRAVELER', 'name' => 'TEST', 'type' => 'ADT', 'check_out_date' => '2026-11-17'];
        $amadeus->addMultiElements('create', [$occupant, $occupant], [
            'loyalty_programs' => ['LEALTAD NUM TST1234 PROGRAMA TEST REWARDS TITULAR TEST/TEST FAVOR DE AGREGAR PUNTOS'],
        ]);

        $this->assertSoapBodyMatchesFixture('pnr-create-occupants', $client->requests[1]['xml']);
    }

    public function test_a_room_list_keyed_by_the_card_holder_alone(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->openSession($amadeus);
        $amadeus->hotelSell([
            'travelAgentRef' => '1',
            [
                'chainCode' => 'MC',
                'cityCode' => 'MEX',
                'hotelCode' => 'MCMEXSFM',
                // Guarantee code 8 (deposit) pays with type 2
                'paymentType' => '2',
                'bookingCode' => 'SM3A00',
                'passengerReference' => [
                    ['value' => '3', 'type' => 'BOP'],
                    ['value' => '2', 'type' => 'BHO'],
                ],
                'ccHolderName' => 'TEST TRAVELER',
                'vendorCode' => 'AX',
                'cardNumber' => '378282246310005',
                'securityId' => '0000',
                'expiryDate' => '1230',
            ],
        ]);

        $this->assertSoapBodyMatchesFixture('hotel-sell-holder-only', $client->requests[1]['xml']);
    }

    public function test_the_end_transaction_reply_names_the_principal_and_the_companion(): void
    {
        $end = AddMultiElementsResponse::fromXml($this->tstFixture('responses/pnr-end-companion.xml'));
        $segment = $end->segments[0];

        $this->assertSame('TST006', $end->pnrNumber);
        $this->assertNotNull($end->travelerByReference($segment->passengerReference));
        $this->assertCount(1, $segment->companions);
        $this->assertSame('ADT', $segment->companions[0]->type);
        $this->assertNotSame($segment->passengerReference, $segment->companions[0]->referenceNumber);
    }
}
