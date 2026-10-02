<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Operations\HotelDescriptiveInfo;
use PHPUnit\Framework\TestCase;

class HotelDescriptiveInfoTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $params = HotelDescriptiveInfoParams::fromArray(['hotelCode' => 'MTYHLT']);
        $operation = new HotelDescriptiveInfo($params);

        $this->assertEquals('Hotel_DescriptiveInfo', $operation->getOperationName());
    }

    public function test_it_builds_single_hotel_request(): void
    {
        $params = HotelDescriptiveInfoParams::fromArray(['hotelCode' => 'MTYHLT']);
        $operation = new HotelDescriptiveInfo($params);
        $body = $operation->build();

        $this->assertArrayHasKey('HotelDescriptiveInfos', $body);
        $info = $body['HotelDescriptiveInfos']['HotelDescriptiveInfo'];
        $this->assertEquals('MTYHLT', $info['_attributes']['HotelCode']);
        $this->assertEquals('true', $info['HotelInfo']['_attributes']['SendData']);
    }

    public function test_it_builds_multiple_hotel_request(): void
    {
        $params = HotelDescriptiveInfoParams::fromArray(['hotelCode' => ['MTYHLT', 'CDMX01']]);
        $operation = new HotelDescriptiveInfo($params);
        $body = $operation->build();

        $infos = $body['HotelDescriptiveInfos']['HotelDescriptiveInfo'];
        $this->assertCount(2, $infos);
        $this->assertEquals('MTYHLT', $infos[0]['_attributes']['HotelCode']);
        $this->assertEquals('CDMX01', $infos[1]['_attributes']['HotelCode']);
    }
}
