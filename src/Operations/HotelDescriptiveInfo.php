<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class HotelDescriptiveInfo implements Operation
{
    public function __construct(
        protected HotelDescriptiveInfoParams $params,
    ) {}

    public function getOperationName(): string
    {
        return 'Hotel_DescriptiveInfo';
    }

    public function build(): array
    {
        $hotelDescriptiveInfo = [];

        if (is_array($this->params->hotelCode)) {
            foreach ($this->params->hotelCode as $code) {
                $hotelDescriptiveInfo[] = $this->buildSingleHotelInfo($code);
            }
        } else {
            $hotelDescriptiveInfo = $this->buildSingleHotelInfo($this->params->hotelCode);
        }

        return [
            // OTA_HotelDescriptiveInfoRQ carries these as attributes
            '_attributes' => [
                'EchoToken' => 'withParsing',
                'Version' => '6.001',
                'PrimaryLangID' => 'en',
            ],
            'HotelDescriptiveInfos' => [
                'HotelDescriptiveInfo' => $hotelDescriptiveInfo,
            ],
        ];
    }

    protected function buildSingleHotelInfo(string $hotelCode): array
    {
        return [
            '_attributes' => ['HotelCode' => $hotelCode],
            'HotelInfo' => [
                '_attributes' => ['SendData' => $this->params->hotelSendData],
            ],
            'FacilityInfo' => [
                '_attributes' => [
                    'SendGuestRooms' => $this->params->sendGuestRooms,
                    'SendMeetingRooms' => $this->params->sendMeetingRooms,
                    'SendRestaurants' => $this->params->sendRestaurants,
                ],
            ],
            'Policies' => [
                '_attributes' => ['SendPolicies' => $this->params->sendPolicies],
            ],
            'AreaInfo' => [
                '_attributes' => [
                    'SendAttractions' => $this->params->sendAttractions,
                    'SendRefPoints' => $this->params->sendRefPoints,
                    'SendRecreations' => $this->params->sendRecreations,
                ],
            ],
            'AffiliationInfo' => [
                '_attributes' => [
                    'SendAwards' => $this->params->sendAwards,
                    'SendLoyalPrograms' => $this->params->sendLoyalPrograms,
                ],
            ],
            'ContactInfo' => [
                '_attributes' => ['SendData' => $this->params->contactSendData],
            ],
            'MultimediaObjects' => [
                '_attributes' => ['SendData' => $this->params->multimediaSendData],
            ],
            'ContentInfos' => [
                'ContentInfo' => [
                    '_attributes' => ['Name' => 'SecureMultimediaURLs'],
                ],
            ],
        ];
    }
}
