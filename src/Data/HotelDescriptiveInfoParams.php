<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Data\Concerns\ValidatesParams;

final readonly class HotelDescriptiveInfoParams
{
    use ValidatesParams;

    public function __construct(
        public string|array $hotelCode,
        public string $hotelSendData = 'true',
        public string $contactSendData = 'true',
        public string $multimediaSendData = 'true',
        public string $sendGuestRooms = 'true',
        public string $sendMeetingRooms = 'true',
        public string $sendRestaurants = 'true',
        public string $sendPolicies = 'true',
        public string $sendAttractions = 'true',
        public string $sendRefPoints = 'true',
        public string $sendRecreations = 'true',
        public string $sendAwards = 'true',
        public string $sendLoyalPrograms = 'true',
    ) {}

    public static function fromArray(array $data): self
    {
        self::validateRequired($data, ['hotelCode'], 'HotelDescriptiveInfoParams');

        return new self(
            hotelCode: $data['hotelCode'],
            hotelSendData: $data['hotelSendData'] ?? 'true',
            contactSendData: $data['contactSendData'] ?? 'true',
            multimediaSendData: $data['multimediaSendData'] ?? 'true',
            sendGuestRooms: $data['sendGuestRooms'] ?? 'true',
            sendMeetingRooms: $data['sendMeetingRooms'] ?? 'true',
            sendRestaurants: $data['sendRestaurants'] ?? 'true',
            sendPolicies: $data['sendPolicies'] ?? 'true',
            sendAttractions: $data['sendAttractions'] ?? 'true',
            sendRefPoints: $data['sendRefPoints'] ?? 'true',
            sendRecreations: $data['sendRecreations'] ?? 'true',
            sendAwards: $data['sendAwards'] ?? 'true',
            sendLoyalPrograms: $data['sendLoyalPrograms'] ?? 'true',
        );
    }
}
