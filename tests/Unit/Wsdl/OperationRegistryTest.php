<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Wsdl;

use Aldogtz\AmadeusSoap\Exceptions\OperationNotFoundException;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use Aldogtz\AmadeusSoap\Wsdl\OperationRegistry;
use PHPUnit\Framework\TestCase;

class OperationRegistryTest extends TestCase
{
    protected function metadata(string $name): OperationMetadata
    {
        return new OperationMetadata(
            name: $name,
            wsdlId: 'abc123',
            wsdlPath: '/tmp/test.wsdl',
            version: '1.0',
            inputMessageName: $name.'_1_0',
            outputMessageName: $name.'Reply_1_0',
            soapAction: 'http://example.test/'.$name,
            serviceEndpoint: 'https://example.test/soap',
            rootElement: $name,
            responseRootElement: $name.'Reply',
            responseNamespace: 'http://example.test/ns',
        );
    }

    public function test_it_registers_and_retrieves_metadata(): void
    {
        $registry = new OperationRegistry;
        $metadata = $this->metadata('Hotel_Sell');

        $registry->register('Hotel_Sell', $metadata);

        $this->assertTrue($registry->has('Hotel_Sell'));
        $this->assertSame($metadata, $registry->get('Hotel_Sell'));
    }

    public function test_has_returns_false_for_unknown_operations(): void
    {
        $this->assertFalse((new OperationRegistry)->has('Hotel_Sell'));
    }

    public function test_get_throws_for_unknown_operations(): void
    {
        $this->expectException(OperationNotFoundException::class);
        $this->expectExceptionMessage("Operation 'Hotel_Sell' is not defined in the WSDL files.");

        (new OperationRegistry)->get('Hotel_Sell');
    }

    public function test_registering_the_same_name_twice_overwrites(): void
    {
        $registry = new OperationRegistry;
        $second = $this->metadata('Hotel_Sell');

        $registry->register('Hotel_Sell', $this->metadata('Hotel_Sell'));
        $registry->register('Hotel_Sell', $second);

        $this->assertCount(1, $registry->all());
        $this->assertSame($second, $registry->get('Hotel_Sell'));
    }

    public function test_all_returns_every_operation_keyed_by_name(): void
    {
        $registry = new OperationRegistry;
        $registry->register('Hotel_Sell', $this->metadata('Hotel_Sell'));
        $registry->register('PNR_Cancel', $this->metadata('PNR_Cancel'));

        $this->assertEquals(['Hotel_Sell', 'PNR_Cancel'], array_keys($registry->all()));
    }
}
