<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;

final readonly class HotelSellParams
{
    use ValidatesParams;

    public function __construct(
        public string $travelAgentRef,
        public array $roomStayData,
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, ['travelAgentRef'], 'HotelSellParams');

        $travelAgentRef = $data['travelAgentRef'];
        $rooms = [];

        foreach ($data as $key => $value) {
            if ($key !== 'travelAgentRef' && is_array($value)) {
                $rooms[] = $value;
            }
        }

        // If no multi-dimensional rooms found, the data itself is a single room
        if (empty($rooms) && isset($data['chainCode'])) {
            $rooms[] = $data;
        }

        return new self(
            travelAgentRef: $travelAgentRef,
            roomStayData: $rooms,
        );
    }

    /**
     * Sell params for one room, taken from the replies the flow already has:
     * the rate (single-hotel search), the PNR created for the traveler and
     * the guarantee card.
     *
     * @return array<string, mixed> The array hotelSell() takes
     *
     * @throws InvalidParameterException
     */
    public static function forRoom(RoomStayResult $roomStay, AddMultiElementsResponse $pnr, PaymentCard $card): array
    {
        $errors = [];
        $holder = $pnr->travelers[0] ?? null;

        if (strlen($roomStay->hotelCode) !== 8) {
            $errors['hotel_code'] = "must be the 8-character Amadeus code (chain, city, property), got '{$roomStay->hotelCode}'";
        }
        if ($pnr->travelAgentRef === '') {
            $errors['travel_agent_ref'] = 'missing from the PNR reply';
        }
        if ($holder === null) {
            $errors['passenger_reference'] = 'the PNR reply has no traveler';
        }

        if ($errors !== []) {
            throw InvalidParameterException::forValidation('HotelSellParams', $errors);
        }

        return [
            'travelAgentRef' => $pnr->travelAgentRef,
            // YZMTY045 = chain YZ, city MTY, property 045
            'chainCode' => substr($roomStay->hotelCode, 0, 2),
            'cityCode' => substr($roomStay->hotelCode, 2, 3),
            'hotelCode' => $roomStay->hotelCode,
            'bookingCode' => $roomStay->bookingCode,
            // BHO: the booking holder occupies the room
            'passengerReference' => ['type' => 'BHO', 'value' => $holder->referenceNumber],
            // As BookingV2 does: guarantee code 8 pays with type 2, any other with 1
            'paymentType' => $roomStay->guaranteeCode === '8' ? '2' : '1',
            'vendorCode' => $card->vendorCode,
            'cardNumber' => $card->number,
            'securityId' => $card->securityCode,
            'expiryDate' => $card->expiry,
            // Holder in firstName with an empty surname: the shape TST accepted
            'firstName' => $card->holderName,
            'surname' => '',
        ];
    }

    /**
     * Accept snake_case keys (travel_agent_ref, booking_code…) in the sell
     * array, including each room of a multi-room sell.
     *
     * @return array<string, mixed>
     */
    public static function normalize(array $params): array
    {
        $params = self::acceptSnakeCase($params);

        foreach ($params as $key => $value) {
            // Rooms of a multi-room sell are nested arrays under any key
            if (is_array($value) && ! in_array($key, ['passengerReference', 'passenger_reference'], true)) {
                $params[$key] = self::acceptSnakeCase($value);
            }
        }

        return $params;
    }
}
