<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Data\PaymentCard;
use Aldogtz\AmadeusSoap\Data\Traveler;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use DOMDocument;
use DOMXPath;
use Illuminate\Support\Carbon;

/**
 * Each step takes what the previous one returned: the requests derived from
 * the replies must be the ones Amadeus TST accepted.
 */
class ResponseDrivenParamsTest extends TestCase
{
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    protected function searchSingle(AmadeusSoap $amadeus)
    {
        return $amadeus->hotelSearch('single', [
            'hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => [],
        ]);
    }

    /**
     * Text of the first element at a slash-separated path under the SOAP Body's root.
     */
    protected function bodyValue(string $sentXml, string $path): ?string
    {
        $dom = new DOMDocument;
        $dom->loadXML($sentXml);

        $steps = array_map(fn (string $name) => "*[local-name()='{$name}']", explode('/', $path));
        $node = (new DOMXPath($dom))->query("//*[local-name()='Body']/*/".implode('/', $steps))->item(0);

        return $node?->textContent;
    }

    public function test_pricing_a_room_stay_sends_the_request_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-pricing');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $room = $this->searchSingle($amadeus)->roomStays[1];
        $pricing = $amadeus->hotelPricing($room);

        $this->assertSame('1KN57JU', $room->bookingCode);
        $this->assertSoapBodyMatchesFixture('hotel-pricing', $client->requests[1]['xml']);
        $this->assertSame('1KN57JU', $pricing->bookingCode);
    }

    public function test_a_traveler_creates_the_pnr_amadeus_accepted(): void
    {
        Carbon::setTestNow('2026-07-31 17:23:00');
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->searchSingle($amadeus);
        $amadeus->addMultiElements('create', new Traveler('TRAVELER', 'TEST'));

        $this->assertSoapBodyMatchesFixture('pnr-create', $client->requests[1]['xml']);
    }

    public function test_selling_a_room_stay_takes_every_value_from_the_replies(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-create', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $room = $this->searchSingle($amadeus)->roomStays[1];
        $pnr = $amadeus->addMultiElements('create', new Traveler('TRAVELER', 'TEST'));
        $amadeus->hotelSell($room, $pnr, new PaymentCard('AX', '378282246310005', '0000', '1230', 'TEST TRAVELER'));

        $sell = $client->requests[2]['xml'];
        $this->assertNotSame('', $pnr->travelAgentRef);
        $this->assertSame($pnr->travelAgentRef, $this->bodyValue($sell, 'travelAgentRef/reference/value'));

        $hotel = 'roomStayData/globalBookingInfo/markerGlobalBookingInfo/hotelReference';
        $this->assertSame('YZ', $this->bodyValue($sell, "{$hotel}/chainCode"));
        $this->assertSame('MTY', $this->bodyValue($sell, "{$hotel}/cityCode"));
        $this->assertSame('045', $this->bodyValue($sell, "{$hotel}/hotelCode"));

        $holder = 'roomStayData/globalBookingInfo/representativeParties/occupantList/passengerReference';
        $this->assertSame('BHO', $this->bodyValue($sell, "{$holder}/type"));
        $this->assertSame($pnr->travelers[0]->referenceNumber, $this->bodyValue($sell, "{$holder}/value"));

        $this->assertSame('1KN57JU', $this->bodyValue($sell, 'roomStayData/roomList/roomRateDetails/hotelProductReference/referenceDetails/value'));
        // GuaranteeCode 31 → payment type 1
        $this->assertSame('1', $this->bodyValue($sell, 'roomStayData/roomList/guaranteeOrDeposit/paymentInfo/paymentDetails/paymentType'));

        $card = 'roomStayData/roomList/guaranteeOrDeposit/groupCreditCardInfo/creditCardInfo/ccInfo';
        $this->assertSame('AX', $this->bodyValue($sell, "{$card}/vendorCode"));
        $this->assertSame('378282246310005', $this->bodyValue($sell, "{$card}/cardNumber"));
        $this->assertSame('1230', $this->bodyValue($sell, "{$card}/expiryDate"));
        $this->assertSame('TEST TRAVELER', $this->bodyValue($sell, "{$card}/firstName"));
        $this->assertSame('', $this->bodyValue($sell, "{$card}/surname"));
    }

    public function test_selling_a_room_stay_needs_the_pnr_and_the_card(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single');
        $amadeus = $this->app->make(AmadeusSoap::class);
        $room = $this->searchSingle($amadeus)->roomStays[1];

        $this->expectException(InvalidParameterException::class);

        try {
            $amadeus->hotelSell($room);
        } finally {
            $this->assertCount(1, $client->requests);
        }
    }

    public function test_after_the_sell_each_step_takes_the_previous_reply(): void
    {
        // PNR_Retrieve starts a new session: the booking one is signed out first
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-end', 'signout', 'pnr-retrieve', 'hotel-complete-reservation-details', 'pnr-end');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->searchSingle($amadeus);
        $end = $amadeus->addMultiElements('end');
        $retrieve = $amadeus->pnrRetrieve($end);
        $amadeus->hotelCompleteReservationDetails($end);
        $amadeus->pnrCancel($retrieve->segments[0]);

        [, , , $retrieveRequest, $detailsRequest, $cancelRequest] = array_column($client->requests, 'xml');

        $this->assertSame('TST002', $end->pnrNumber);
        $this->assertSame('TST002', $this->bodyValue($retrieveRequest, 'retrievalFacts/reservationOrProfileIdentifier/reservation/controlNumber'));

        $this->assertSame('TST002', $this->bodyValue($detailsRequest, 'retrievalKeyGroup/retrievalKey/reservation/controlNumber'));
        $this->assertSame($end->segments[0]->segmentNumber, $this->bodyValue($detailsRequest, 'retrievalKeyGroup/tattooID/referenceDetails/value'));

        $this->assertSame($retrieve->segments[0]->segmentNumber, $this->bodyValue($cancelRequest, 'cancelElements/element/number'));
    }

    public function test_descriptive_info_takes_a_room_stay(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-descriptive-info');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelDescriptiveInfo($this->searchSingle($amadeus)->roomStays[0]);

        $this->assertSoapBodyMatchesFixture('hotel-descriptive-info', $client->requests[1]['xml']);
    }

    public function test_snake_case_sell_keys_send_the_request_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'hotel-sell');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $this->searchSingle($amadeus);
        $amadeus->hotelSell([
            'travel_agent_ref' => '1',
            'chain_code' => 'YZ',
            'city_code' => 'MTY',
            'hotel_code' => 'YZMTY045',
            'booking_code' => '1KN57JU',
            'passenger_reference' => ['type' => 'BHO', 'value' => '2'],
            'payment_type' => '1',
            'vendor_code' => 'AX',
            'card_number' => '378282246310005',
            'security_id' => '0000',
            'expiry_date' => '1230',
            'surname' => 'TRAVELER',
            'first_name' => 'TEST',
        ]);

        $this->assertSoapBodyMatchesFixture('hotel-sell', $client->requests[1]['xml']);
    }
}
