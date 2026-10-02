<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Operations\HotelSell;
use PHPUnit\Framework\TestCase;

class HotelSellTest extends TestCase
{
    protected function room(array $card): array
    {
        return array_merge([
            'chainCode' => 'YZ',
            'cityCode' => 'MTY',
            'hotelCode' => 'YZMTY045',
            'bookingCode' => '1KN57JU',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
            'paymentType' => '1',
            'vendorCode' => 'VI',
            'cardNumber' => '4111111111111111',
            'securityId' => '123',
            'expiryDate' => '1230',
        ], $card);
    }

    protected function cardOf(array $roomStayData): array
    {
        return $roomStayData['roomList']['guaranteeOrDeposit']['groupCreditCardInfo']['creditCardInfo']['ccInfo'];
    }

    public function test_a_holder_name_alone_is_sent_alone(): void
    {
        // The multi-room shape BookingV2 sells with in production
        $body = (new HotelSell([
            'travelAgentRef' => '1',
            $this->room(['ccHolderName' => 'JANE DOE']),
            $this->room(['ccHolderName' => 'JOHN DOE']),
        ]))->build();

        $this->assertSame([
            'vendorCode' => 'VI',
            'cardNumber' => '4111111111111111',
            'securityId' => '123',
            'expiryDate' => '1230',
            'ccHolderName' => 'JANE DOE',
        ], $this->cardOf($body['roomStayData'][0]));
        $this->assertSame('JOHN DOE', $this->cardOf($body['roomStayData'][1])['ccHolderName']);
    }

    public function test_first_name_and_surname_make_the_holder_name(): void
    {
        $body = (new HotelSell(['travelAgentRef' => '1'] + $this->room(['firstName' => 'TEST', 'surname' => 'TRAVELER'])))->build();

        $card = $this->cardOf($body['roomStayData']);
        $this->assertSame('TEST TRAVELER', $card['ccHolderName']);
        $this->assertSame('TRAVELER', $card['surname']);
        $this->assertSame('TEST', $card['firstName']);
    }

    public function test_the_holder_name_has_no_padding_when_the_surname_is_empty(): void
    {
        // HotelSellParams::forRoom() puts the holder in firstName
        $body = (new HotelSell(['travelAgentRef' => '1'] + $this->room(['firstName' => 'TEST TRAVELER', 'surname' => ''])))->build();

        $card = $this->cardOf($body['roomStayData']);
        $this->assertSame('TEST TRAVELER', $card['ccHolderName']);
        $this->assertSame('', $card['surname']);
    }

    public function test_an_explicit_holder_name_wins_over_the_names(): void
    {
        $body = (new HotelSell(['travelAgentRef' => '1'] + $this->room([
            'ccHolderName' => 'ENLACEFORTE',
            'firstName' => 'TEST',
            'surname' => 'TRAVELER',
        ])))->build();

        $card = $this->cardOf($body['roomStayData']);
        $this->assertSame('ENLACEFORTE', $card['ccHolderName']);
        $this->assertSame('TEST', $card['firstName']);
    }
}
