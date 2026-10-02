<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Responses;

use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelDescriptiveInfoResponse;
use PHPUnit\Framework\TestCase;

class HotelDescriptiveInfoResponseTest extends TestCase
{
    protected function descriptiveInfoXml(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <OTA_HotelDescriptiveInfoRS xmlns="http://www.opentravel.org/OTA/2003/05">
                    <HotelDescriptiveContents>
                        <HotelDescriptiveContent HotelCode="MTYHLT">
                            <HotelInfo>
                                <Position Latitude="25.67507" Longitude="-100.31847"/>
                                <Address>
                                    <AddressLine>Av. Insurgentes 1234</AddressLine>
                                    <CityName>Monterrey</CityName>
                                    <PostalCode>64000</PostalCode>
                                    <CountryName Code="MX">Mexico</CountryName>
                                    <StateProv StateCode="NL">Nuevo Leon</StateProv>
                                </Address>
                                <Descriptions>
                                    <MultimediaDescriptions>
                                        <MultimediaDescription InfoCode="1" AdditionalDetailCode="MAIN">
                                            <TextItems>
                                                <TextItem>
                                                    <Description>Welcome to Hilton MTY</Description>
                                                    <Description>The best hotel in the city</Description>
                                                </TextItem>
                                            </TextItems>
                                            <ImageItems>
                                                <ImageItem Category="EXTERIOR">
                                                    <ImageFormat DimensionCategory="J">
                                                        <URL>https://example.com/exterior_j.jpg</URL>
                                                    </ImageFormat>
                                                    <ImageFormat DimensionCategory="F">
                                                        <URL>https://example.com/exterior_f.jpg</URL>
                                                    </ImageFormat>
                                                    <Description>Hotel Exterior</Description>
                                                </ImageItem>
                                            </ImageItems>
                                        </MultimediaDescription>
                                    </MultimediaDescriptions>
                                </Descriptions>
                            </HotelInfo>
                            <AreaInfo>
                                <Attractions>
                                    <Attraction AttractionName="Central Park" AttractionCategoryCode="SHP">
                                        <RefPoints>
                                            <RefPoint Distance="1.5" UnitOfMeasureCode="1" ToFrom="FromFacility"/>
                                        </RefPoints>
                                    </Attraction>
                                </Attractions>
                                <RefPoints>
                                    <RefPoint Name="Airport MTY" Distance="15.0" UnitOfMeasureCode="1" ToFrom="FromFacility"/>
                                </RefPoints>
                            </AreaInfo>
                            <FacilityInfo>
                                <GuestRooms>
                                    <GuestRoom>
                                        <TypeRoom RoomTypeCode="A1K" Name="King Standard"/>
                                        <Amenities>
                                            <Amenity RoomAmenityCode="74"/>
                                            <Amenity RoomAmenityCode="14"/>
                                        </Amenities>
                                    </GuestRoom>
                                </GuestRooms>
                                <Restaurants>
                                    <Restaurant RestaurantName="Lobby Bar">
                                        <ContactInfos>
                                            <ContactInfo>
                                                <Addresses>
                                                    <Address><CityName>Not the hotel</CityName></Address>
                                                </Addresses>
                                            </ContactInfo>
                                        </ContactInfos>
                                    </Restaurant>
                                </Restaurants>
                            </FacilityInfo>
                            <ContactInfos>
                                <ContactInfo>
                                    <Addresses>
                                        <Address UseType="7">
                                            <AddressLine>Av. Insurgentes 1234</AddressLine>
                                            <AddressLine>Col. Centro</AddressLine>
                                            <CityName>Monterrey</CityName>
                                            <PostalCode>64000</PostalCode>
                                            <CountryName Code="MX">Mexico</CountryName>
                                        </Address>
                                    </Addresses>
                                </ContactInfo>
                            </ContactInfos>
                        </HotelDescriptiveContent>
                    </HotelDescriptiveContents>
                </OTA_HotelDescriptiveInfoRS>
            </soapenv:Body>
        </soapenv:Envelope>';
    }

    public function test_it_parses_hotel_content(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $this->assertCount(1, $response->hotels);
        $hotel = $response->hotels[0];
        $this->assertEquals('MTYHLT', $hotel->hotelCode);
    }

    public function test_it_parses_position(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $hotel = $response->hotel();
        $this->assertNotNull($hotel->position);
        $this->assertEquals('25.67507', $hotel->position->latitude);
        $this->assertEquals('-100.31847', $hotel->position->longitude);
    }

    public function test_it_parses_info_address(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $address = $response->hotel()->infoAddress;
        $this->assertEquals('Av. Insurgentes 1234', $address->addressLine);
        $this->assertEquals('Monterrey', $address->cityName);
        $this->assertEquals('64000', $address->postalCode);
        $this->assertEquals('MX', $address->countryCode);
        $this->assertEquals('Mexico', $address->countryName);
        $this->assertEquals('NL', $address->stateCode);
        $this->assertEquals('Nuevo Leon', $address->stateName);
    }

    public function test_it_parses_addresses(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        // The restaurant's ContactInfos are not the property's
        $addresses = $response->hotel()->addresses;
        $this->assertCount(1, $addresses);
        $this->assertEquals('7', $addresses[0]->useType);
        $this->assertSame("Av. Insurgentes 1234\nCol. Centro", $addresses[0]->addressLine);
        $this->assertSame('Monterrey', $addresses[0]->cityName);
    }

    public function test_it_parses_texts(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $texts = $response->hotel()->texts;
        $this->assertCount(1, $texts);
        $this->assertEquals('1', $texts[0]->infoCode);
        $this->assertStringContainsString('Welcome to Hilton MTY', $texts[0]->description);
    }

    public function test_it_parses_image_groups(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $imageGroups = $response->hotel()->imageGroups;
        $this->assertCount(1, $imageGroups);
        $this->assertCount(1, $imageGroups[0]->items);
        $this->assertEquals('https://example.com/exterior_j.jpg', $imageGroups[0]->items[0]->url);
        $this->assertEquals('EXTERIOR', $imageGroups[0]->items[0]->category);
    }

    public function test_it_parses_thumbnail_url(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $this->assertEquals('https://example.com/exterior_f.jpg', $response->hotel()->thumbnailUrl);
    }

    public function test_it_parses_attractions(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $attractions = $response->hotel()->attractions;
        $this->assertCount(1, $attractions);
        $this->assertEquals('Central Park', $attractions[0]->name);
        $this->assertEquals('SHP', $attractions[0]->categoryCode);
        $this->assertCount(1, $attractions[0]->refPoints);
        $this->assertEquals('1.5', $attractions[0]->refPoints[0]->distance);
    }

    public function test_it_parses_area_ref_points(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $refPoints = $response->hotel()->areaRefPoints;
        $this->assertCount(1, $refPoints);
        $this->assertEquals('Airport MTY', $refPoints[0]->name);
        $this->assertEquals('15.0', $refPoints[0]->distance);
    }

    public function test_it_parses_guest_rooms(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $guestRooms = $response->hotel()->guestRooms;
        $this->assertCount(1, $guestRooms);
        $this->assertEquals('A1K', $guestRooms[0]->roomTypeCode);
        $this->assertEquals('King Standard', $guestRooms[0]->name);
        $this->assertEquals(['74', '14'], $guestRooms[0]->amenityCodes);
    }

    public function test_hotel_convenience_method(): void
    {
        $raw = new AmadeusResponse($this->descriptiveInfoXml(), 'http://www.opentravel.org/OTA/2003/05');
        $response = HotelDescriptiveInfoResponse::fromResponse($raw);

        $this->assertNotNull($response->hotel('MTYHLT'));
        $this->assertNull($response->hotel('NONEXIST'));
    }
}
