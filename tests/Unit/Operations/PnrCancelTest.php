<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Operations\PnrCancel;
use PHPUnit\Framework\TestCase;

class PnrCancelTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => '2']);
        $operation = new PnrCancel($params);

        $this->assertEquals('PNR_Cancel', $operation->getOperationName());
    }

    public function test_it_builds_single_segment_cancel(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => '3']);
        $operation = new PnrCancel($params);
        $body = $operation->build();

        $this->assertEquals('0', $body['pnrActions']['optionCode']);
        $this->assertEquals('E', $body['cancelElements']['entryType']);
        $this->assertEquals('ST', $body['cancelElements']['element']['identifier']);
        $this->assertEquals('3', $body['cancelElements']['element']['number']);
    }

    public function test_it_builds_multi_segment_cancel(): void
    {
        $params = PnrCancelParams::fromArray(['segmentNumber' => ['2', '3', '4']]);
        $operation = new PnrCancel($params);
        $body = $operation->build();

        $this->assertCount(3, $body['cancelElements']);
        $this->assertEquals('2', $body['cancelElements'][0]['element']['number']);
        $this->assertEquals('3', $body['cancelElements'][1]['element']['number']);
        $this->assertEquals('4', $body['cancelElements'][2]['element']['number']);
    }
}
