<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;
use Aldogtz\AmadeusSoap\Operations\HotelCompleteReservationDetails;
use Aldogtz\AmadeusSoap\Operations\HotelDescriptiveInfo;
use Aldogtz\AmadeusSoap\Operations\HotelPricing;
use Aldogtz\AmadeusSoap\Operations\HotelSearch;
use Aldogtz\AmadeusSoap\Operations\HotelSell;
use Aldogtz\AmadeusSoap\Operations\PnrAddMultiElements;
use Aldogtz\AmadeusSoap\Operations\PnrCancel;
use Aldogtz\AmadeusSoap\Operations\PnrRetrieve;
use Aldogtz\AmadeusSoap\Operations\SecuritySignOut;
use PHPUnit\Framework\TestCase;

class OperationInterfaceTest extends TestCase
{
    public function test_hotel_search_implements_operation(): void
    {
        $params = HotelSearchParams::fromArray(['hotel_city_code' => 'MTY', 'start' => '2026-03-01', 'end' => '2026-03-03']);
        $operation = new HotelSearch($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Hotel_MultiSingleAvailability', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_hotel_pricing_implements_operation(): void
    {
        $params = HotelPricingParams::fromArray([
            'start' => '2026-03-01',
            'end' => '2026-03-03',
            'hotel_code' => 'MTYHLT',
            'rate_plan_code' => 'RAC',
            'booking_code' => 'ABCDE',
            'room_type_code' => 'A1K',
            'quantity' => '1',
            'guest_count' => '1',
        ]);
        $operation = new HotelPricing($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Hotel_EnhancedPricing', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_hotel_sell_implements_operation(): void
    {
        $operation = new HotelSell(['travelAgentRef' => '5', 'chainCode' => 'HI', 'cityCode' => 'MTY', 'hotelCode' => 'HIMTYHLT', 'bookingCode' => 'ABCDE', 'passengerReference' => ['type' => 'BHO', 'value' => '1'], 'paymentType' => '5', 'vendorCode' => 'VI', 'cardNumber' => '4111111111111111', 'securityId' => '123', 'expiryDate' => '1225', 'surname' => 'GARCIA', 'firstName' => 'JUAN']);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Hotel_Sell', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_hotel_descriptive_info_implements_operation(): void
    {
        $params = HotelDescriptiveInfoParams::fromArray(['hotelCode' => 'MTYHLT']);
        $operation = new HotelDescriptiveInfo($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Hotel_DescriptiveInfo', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_hotel_complete_reservation_details_implements_operation(): void
    {
        $params = HotelCompleteReservationDetailsParams::fromArray(['pnrNumber' => 'ABC123', 'segmentNumber' => '2']);
        $operation = new HotelCompleteReservationDetails($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Hotel_CompleteReservationDetails', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_pnr_add_multi_elements_implements_operation(): void
    {
        $operation = new PnrAddMultiElements(
            type: 'create',
            params: ['surname' => 'GARCIA', 'name' => 'JUAN', 'type' => 'ADT'],
        );

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('PNR_AddMultiElements', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_pnr_retrieve_implements_operation(): void
    {
        $params = PnrRetrieveParams::fromArray(['pnrNumber' => 'ABC123']);
        $operation = new PnrRetrieve($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('PNR_Retrieve', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_pnr_cancel_implements_operation(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => '2']);
        $operation = new PnrCancel($params);

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('PNR_Cancel', $operation->getOperationName());
        $this->assertIsArray($operation->build());
    }

    public function test_security_sign_out_implements_operation(): void
    {
        $operation = new SecuritySignOut;

        $this->assertInstanceOf(Operation::class, $operation);
        $this->assertEquals('Security_SignOut', $operation->getOperationName());
        $this->assertIsArray($operation->build());
        $this->assertEmpty($operation->build());
    }
}
