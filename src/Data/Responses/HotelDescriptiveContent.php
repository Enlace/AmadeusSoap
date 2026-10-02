<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\Responses\Values\Address;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Attraction;
use Aldogtz\AmadeusSoap\Data\Responses\Values\GuestRoom;
use Aldogtz\AmadeusSoap\Data\Responses\Values\ImageGroup;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Position;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RefPoint;
use Aldogtz\AmadeusSoap\Data\Responses\Values\TextItem;

final readonly class HotelDescriptiveContent
{
    /**
     * @param  Address[]  $addresses
     * @param  TextItem[]  $texts
     * @param  ImageGroup[]  $imageGroups
     * @param  Attraction[]  $attractions
     * @param  RefPoint[]  $areaRefPoints
     * @param  Address  $infoAddress  The street address: HotelInfo/Address when the reply has one,
     *                                 otherwise the physical (UseType 7) contact address, otherwise
     *                                 the first one; empty strings when the reply has no address
     * @param  Address[]  $addresses  ContactInfos/ContactInfo/Addresses, in reply order
     * @param  GuestRoom[]  $guestRooms
     * @param  string  $checkInTime  PolicyInfo@CheckInTime, e.g. 15:00:00
     */
    public function __construct(
        public string $hotelCode,
        public ?Position $position,
        public Address $infoAddress,
        public array $addresses,
        public array $texts,
        public array $imageGroups,
        public string $thumbnailUrl,
        public array $attractions,
        public array $areaRefPoints,
        public array $guestRooms,
        public string $hotelName = '',
        public string $chainCode = '',
        public string $checkInTime = '',
        public string $checkOutTime = '',
    ) {}
}
