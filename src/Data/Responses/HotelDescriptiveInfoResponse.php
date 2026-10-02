<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Concerns\ParsesAmadeusXml;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Address;
use Aldogtz\AmadeusSoap\Data\Responses\Values\AmadeusError;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Attraction;
use Aldogtz\AmadeusSoap\Data\Responses\Values\GuestRoom;
use Aldogtz\AmadeusSoap\Data\Responses\Values\HotelImage;
use Aldogtz\AmadeusSoap\Data\Responses\Values\ImageGroup;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Position;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RefPoint;
use Aldogtz\AmadeusSoap\Data\Responses\Values\TextItem;

final class HotelDescriptiveInfoResponse
{
    use ParsesAmadeusXml;

    /**
     * @param  AmadeusError[]  $errors
     * @param  HotelDescriptiveContent[]  $hotels
     */
    public function __construct(
        public readonly bool $hasErrors,
        public readonly array $errors,
        public readonly array $hotels,
        public readonly AmadeusResponse $raw,
    ) {}

    public static function fromResponse(AmadeusResponse $response): self
    {
        $errors = self::parseOtaErrors($response);

        $hotels = [];
        $contentNodes = self::nodes($response, '//res:HotelDescriptiveContent');

        foreach ($contentNodes as $node) {
            $hotels[] = self::parseContent($response, $node);
        }

        return new self(
            hasErrors: count($errors) > 0,
            errors: $errors,
            hotels: $hotels,
            raw: $response,
        );
    }

    /**
     * Get a hotel by its code. Convenience for single-hotel lookups.
     */
    public function hotel(?string $hotelCode = null): ?HotelDescriptiveContent
    {
        if ($hotelCode === null) {
            return $this->hotels[0] ?? null;
        }

        foreach ($this->hotels as $hotel) {
            if ($hotel->hotelCode === $hotelCode) {
                return $hotel;
            }
        }

        return null;
    }

    private static function parseContent(AmadeusResponse $response, \DOMNode $node): HotelDescriptiveContent
    {
        $hotelCode = self::str($response, './@HotelCode', $node);

        // Position
        $lat = self::str($response, './res:HotelInfo/res:Position/@Latitude', $node);
        $lng = self::str($response, './res:HotelInfo/res:Position/@Longitude', $node);
        $position = ($lat !== '' || $lng !== '') ? new Position($lat, $lng) : null;

        // Addresses: the property's are under ContactInfos (restaurants
        // have their own ContactInfos deeper in FacilityInfo)
        $addresses = [];
        foreach (self::nodes($response, './res:ContactInfos/res:ContactInfo/res:Addresses/res:Address', $node) as $addrNode) {
            $addresses[] = self::addressFrom($response, $addrNode);
        }

        // Amadeus replies carry no HotelInfo/Address; when it is missing the
        // street address is the physical one (UseType 7), else the first
        $infoAddressNode = self::nodes($response, './res:HotelInfo/res:Address', $node)->item(0);
        $infoAddress = $infoAddressNode !== null
            ? self::addressFrom($response, $infoAddressNode)
            : self::physicalAddress($addresses);

        // Texts
        $texts = [];
        $textItemNodes = self::nodes($response, './/res:TextItems/res:TextItem', $node);
        foreach ($textItemNodes as $textNode) {
            $descriptions = [];
            $descNodes = self::nodes($response, './res:Description', $textNode);
            foreach ($descNodes as $descNode) {
                $descriptions[] = $descNode->nodeValue;
            }

            $texts[] = new TextItem(
                infoCode: self::str($response, '../../@InfoCode', $textNode),
                additionalDetailCode: self::str($response, '../../@AdditionalDetailCode', $textNode),
                description: implode("\n", $descriptions),
            );
        }

        // Images
        $imageGroups = [];
        $mmDescNodes = self::nodes($response, ".//res:MultimediaDescription[./res:ImageItems/res:ImageItem/res:ImageFormat/@DimensionCategory = 'J']", $node);
        foreach ($mmDescNodes as $mmNode) {
            $items = [];
            $formatNodes = self::nodes($response, "./res:ImageItems/res:ImageItem/res:ImageFormat[@DimensionCategory = 'J']", $mmNode);
            foreach ($formatNodes as $fmtNode) {
                $desc = self::str($response, '../res:Description', $fmtNode);

                $items[] = new HotelImage(
                    category: self::str($response, '../@Category', $fmtNode),
                    url: self::str($response, './res:URL', $fmtNode),
                    description: $desc !== '' ? $desc : self::str($response, '../res:Description/@Caption', $fmtNode),
                    dimensionCategory: 'J',
                );
            }

            $imageGroups[] = new ImageGroup(
                infoCode: self::str($response, './@InfoCode', $mmNode),
                additionalDetailCode: self::str($response, './@AdditionalDetailCode', $mmNode),
                items: $items,
            );
        }

        // Full-size thumbnail (used in multi-hotel search for first image)
        $thumbnailUrl = self::str(
            $response,
            "./res:HotelInfo/res:Descriptions/res:MultimediaDescriptions/res:MultimediaDescription/res:ImageItems/res:ImageItem/res:ImageFormat[@DimensionCategory = 'F']/res:URL",
            $node,
        );

        // Attractions
        $attractions = [];
        $attractionNodes = self::nodes($response, './/res:Attractions/res:Attraction', $node);
        foreach ($attractionNodes as $attrNode) {
            $refPoints = [];
            $refNodes = self::nodes($response, './res:RefPoints/res:RefPoint', $attrNode);
            foreach ($refNodes as $refNode) {
                $refPoints[] = new RefPoint(
                    name: '',
                    distance: self::str($response, './@Distance', $refNode),
                    unitOfMeasureCode: self::str($response, './@UnitOfMeasureCode', $refNode),
                    toFrom: self::str($response, './@ToFrom', $refNode),
                );
            }

            $attractions[] = new Attraction(
                name: self::str($response, './@AttractionName', $attrNode),
                categoryCode: self::str($response, './@AttractionCategoryCode', $attrNode),
                refPoints: $refPoints,
            );
        }

        // Area RefPoints
        $areaRefPoints = [];
        $areaRefNodes = self::nodes($response, './/res:AreaInfo/res:RefPoints/res:RefPoint', $node);
        foreach ($areaRefNodes as $refNode) {
            $areaRefPoints[] = new RefPoint(
                name: self::str($response, './@Name', $refNode),
                distance: self::str($response, './@Distance', $refNode),
                unitOfMeasureCode: self::str($response, './@UnitOfMeasureCode', $refNode),
                toFrom: self::str($response, './@ToFrom', $refNode),
            );
        }

        // Guest Rooms
        $guestRooms = [];
        $guestRoomNodes = self::nodes($response, './/res:GuestRooms/res:GuestRoom', $node);
        foreach ($guestRoomNodes as $grNode) {
            $amenityCodes = [];
            $amenityNodes = self::nodes($response, './res:Amenities/res:Amenity', $grNode);
            foreach ($amenityNodes as $amenityNode) {
                $code = self::str($response, './@RoomAmenityCode', $amenityNode);
                if ($code !== '') {
                    $amenityCodes[] = $code;
                }
            }

            $guestRooms[] = new GuestRoom(
                roomTypeCode: self::str($response, './res:TypeRoom/@RoomTypeCode', $grNode),
                name: self::str($response, './res:TypeRoom/@Name', $grNode),
                amenityCodes: $amenityCodes,
            );
        }

        return new HotelDescriptiveContent(
            hotelCode: $hotelCode,
            position: $position,
            infoAddress: $infoAddress,
            addresses: $addresses,
            texts: $texts,
            imageGroups: $imageGroups,
            thumbnailUrl: $thumbnailUrl,
            attractions: $attractions,
            areaRefPoints: $areaRefPoints,
            guestRooms: $guestRooms,
            hotelName: self::str($response, './@HotelName', $node),
            chainCode: self::str($response, './@ChainCode', $node),
            checkInTime: self::str($response, './res:Policies/res:Policy/res:PolicyInfo/@CheckInTime', $node),
            checkOutTime: self::str($response, './res:Policies/res:Policy/res:PolicyInfo/@CheckOutTime', $node),
        );
    }

    /**
     * @param  Address[]  $addresses
     */
    private static function physicalAddress(array $addresses): Address
    {
        foreach ($addresses as $address) {
            if ($address->useType === '7') {
                return $address;
            }
        }

        return $addresses[0] ?? new Address('', '', '', '', '', '', '', '');
    }
}
