<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Params;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Data\HotelSellParams;
use Aldogtz\AmadeusSoap\Data\PaymentCard;
use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;
use Aldogtz\AmadeusSoap\Data\Responses\Values\MealsIncluded;
use Aldogtz\AmadeusSoap\Data\Traveler;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use PHPUnit\Framework\TestCase;

class DerivedParamsTest extends TestCase
{
    protected function roomStay(string $hotelCode = 'YZMTY045', string $guaranteeCode = '31', int $adults = 2, array $children = []): RoomStayResult
    {
        return new RoomStayResult(
            rph: '1',
            roomType: 'S1K',
            roomTypeCode: '*1K',
            bookingCode: '1KN57JU',
            ratePlanCode: '57J',
            ratePlanCategory: 'Converted:BAR:P',
            guaranteeCode: $guaranteeCode,
            numberOfUnits: '1',
            nonRefundable: false,
            total: null,
            currency: 'MXN',
            start: '2026-08-30',
            end: '2026-08-31',
            dailyRates: [],
            amenities: [],
            meals: new MealsIncluded('', '', ''),
            hotelCode: $hotelCode,
            adults: $adults,
            children: $children,
        );
    }

    protected function pnr(string $travelAgentRef = '1', bool $withTraveler = true): AddMultiElementsResponse
    {
        $traveler = $withTraveler ? <<<'XML'
            <travellerInfo>
                <elementManagementPassenger><reference><qualifier>PT</qualifier><number>2</number></reference><segmentName>NM</segmentName></elementManagementPassenger>
                <passengerData><travellerInformation><traveller><surname>DOE</surname></traveller><passenger><firstName>JOHN</firstName><type>ADT</type></passenger></travellerInformation></passengerData>
            </travellerInfo>
            XML : '';

        $xml = <<<XML
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
                <PNR_Reply xmlns="http://xml.amadeus.com/PNRACC_21_1_1A">
                    {$traveler}
                    <dataElementsMaster><dataElementsIndiv>
                        <elementManagementData><reference><qualifier>OT</qualifier><number>{$travelAgentRef}</number></reference><segmentName>AP</segmentName></elementManagementData>
                    </dataElementsIndiv></dataElementsMaster>
                </PNR_Reply>
            </soap:Body></soap:Envelope>
            XML;

        return AddMultiElementsResponse::fromResponse(new AmadeusResponse($xml, 'http://xml.amadeus.com/PNRACC_21_1_1A'));
    }

    protected function card(): PaymentCard
    {
        return new PaymentCard('VI', '4111111111111111', '123', '1230', 'JOHN DOE');
    }

    // --- Pricing from a room stay ---

    public function test_pricing_takes_hotel_dates_codes_and_occupancy_from_the_room_stay(): void
    {
        $params = HotelPricingParams::fromRoomStay($this->roomStay(children: [['age' => '5', 'count' => '1']]));

        $this->assertSame('YZMTY045', $params->hotelCode);
        $this->assertSame('2026-08-30', $params->start);
        $this->assertSame('2026-08-31', $params->end);
        $this->assertSame('57J', $params->ratePlanCode);
        $this->assertSame('1KN57JU', $params->bookingCode);
        $this->assertSame('*1K', $params->roomTypeCode);
        $this->assertSame('1', $params->quantity);
        $this->assertSame('2', $params->guestCount);
        $this->assertSame([['age' => '5', 'count' => '1']], $params->children);
    }

    public function test_pricing_overrides_win_and_unknown_occupancy_means_one_adult(): void
    {
        $params = HotelPricingParams::fromRoomStay($this->roomStay(adults: 0), ['quantity' => '2']);

        $this->assertSame('1', $params->guestCount);
        $this->assertSame('2', $params->quantity);
    }

    // --- Sell from a room stay ---

    public function test_sell_takes_every_value_from_the_replies_and_the_card(): void
    {
        $params = HotelSellParams::forRoom($this->roomStay(), $this->pnr('7'), $this->card());

        $this->assertSame('7', $params['travelAgentRef']);
        $this->assertSame('YZ', $params['chainCode']);
        $this->assertSame('MTY', $params['cityCode']);
        $this->assertSame('YZMTY045', $params['hotelCode']);
        $this->assertSame('1KN57JU', $params['bookingCode']);
        $this->assertSame(['type' => 'BHO', 'value' => '2'], $params['passengerReference']);
        $this->assertSame('1', $params['paymentType']);
        $this->assertSame('4111111111111111', $params['cardNumber']);
        $this->assertSame('JOHN DOE', $params['firstName']);
        $this->assertSame('', $params['surname']);
    }

    public function test_guarantee_code_8_pays_with_type_2(): void
    {
        $params = HotelSellParams::forRoom($this->roomStay(guaranteeCode: '8'), $this->pnr(), $this->card());

        $this->assertSame('2', $params['paymentType']);
    }

    public function test_sell_rejects_what_it_cannot_derive(): void
    {
        try {
            HotelSellParams::forRoom($this->roomStay(hotelCode: 'MTY045'), $this->pnr('', withTraveler: false), $this->card());
            $this->fail('Expected InvalidParameterException');
        } catch (InvalidParameterException $e) {
            $this->assertSame(['hotel_code', 'travel_agent_ref', 'passenger_reference'], array_keys($e->getValidationErrors()));
        }
    }

    // --- snake_case keys ---

    public function test_sell_accepts_snake_case_keys_in_every_room(): void
    {
        $params = HotelSellParams::normalize([
            'travel_agent_ref' => '1',
            ['chain_code' => 'YZ', 'booking_code' => 'A', 'passenger_reference' => ['type' => 'BHO', 'value' => '2']],
            ['chain_code' => 'HI', 'booking_code' => 'B'],
        ]);

        $this->assertSame('1', $params['travelAgentRef']);
        $this->assertSame('YZ', $params[0]['chainCode']);
        $this->assertSame(['type' => 'BHO', 'value' => '2'], $params[0]['passengerReference']);
        $this->assertSame('B', $params[1]['bookingCode']);
    }

    public function test_camel_case_params_accept_snake_case_keys(): void
    {
        $this->assertSame('ABC123', PnrRetrieveParams::fromArray(['pnr_number' => 'ABC123'])->pnrNumber);
        $this->assertSame('2', PnrCancelParams::fromArray(['segment_number' => '2'])->segmentNumber);

        $details = HotelCompleteReservationDetailsParams::fromArray(['pnr_number' => 'ABC123', 'segment_number' => '2']);
        $this->assertSame('ABC123', $details->pnrNumber);
        $this->assertSame('2', $details->segmentNumber);

        $info = HotelDescriptiveInfoParams::fromArray(['hotel_code' => 'YZMTY045', 'send_policies' => 'false']);
        $this->assertSame('YZMTY045', $info->hotelCode);
        $this->assertSame('false', $info->sendPolicies);
    }

    public function test_an_explicit_camel_case_key_wins(): void
    {
        $this->assertSame('CAMEL1', PnrRetrieveParams::fromArray(['pnrNumber' => 'CAMEL1', 'pnr_number' => 'SNAKE1'])->pnrNumber);
    }

    // --- Value objects ---

    public function test_a_traveler_maps_to_pnr_params(): void
    {
        $this->assertSame(['surname' => 'DOE', 'name' => 'JOHN', 'type' => 'ADT'], (new Traveler('DOE', 'JOHN'))->toArray());
        $this->assertSame('CHD', (new Traveler('DOE', 'ANA', 'CHD'))->toArray()['type']);
    }

    public function test_the_card_does_not_leak_number_or_cvc_when_dumped(): void
    {
        $card = $this->card();

        ob_start();
        var_dump($card);
        $dump = ob_get_clean();

        $this->assertSame('XXXXXXXXXXXX1111', $card->maskedNumber());
        $this->assertStringContainsString('XXXXXXXXXXXX1111', $dump);
        $this->assertStringNotContainsString('4111111111111111', $dump);
        $this->assertStringNotContainsString('"123"', $dump);
    }
}
