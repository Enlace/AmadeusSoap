<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Client;

use Aldogtz\AmadeusSoap\Client\AmadeusSoapClient;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;
use PHPUnit\Framework\TestCase;

class SoapClientFactoryTest extends TestCase
{
    protected function wsdl(string $file = 'Hotel_v1.wsdl'): string
    {
        return dirname(__DIR__, 2).'/Fixtures/wsdl/'.$file;
    }

    public function test_it_builds_a_client_from_a_wsdl_file(): void
    {
        $client = (new SoapClientFactory)->create($this->wsdl());

        $this->assertInstanceOf(AmadeusSoapClient::class, $client);
    }

    public function test_the_wsdl_operations_are_visible_to_the_client(): void
    {
        // Guards the fixture too: PHP's WSDL parser is stricter than the
        // XPath extraction WsdlManager does.
        $client = (new SoapClientFactory)->create($this->wsdl());

        $this->assertEqualsCanonicalizing(
            ['Hotel_MultiSingleAvailability', 'Hotel_DescriptiveInfo'],
            array_keys($client->__getFunctions() ? $this->operationsOf($client) : []),
        );
    }

    /** @return array<string, true> */
    protected function operationsOf(AmadeusSoapClient $client): array
    {
        $operations = [];

        foreach ($client->__getFunctions() as $signature) {
            // "anyType Hotel_DescriptiveInfo(anyType $Body)"
            if (preg_match('/\s(\w+)\(/', $signature, $matches)) {
                $operations[$matches[1]] = true;
            }
        }

        return $operations;
    }

    public function test_clients_are_pooled_per_wsdl_path(): void
    {
        $factory = new SoapClientFactory;

        $first = $factory->create($this->wsdl());
        $second = $factory->create($this->wsdl());

        $this->assertSame($first, $second);
        $this->assertEquals(1, $factory->poolSize());
    }

    public function test_different_wsdls_get_different_clients(): void
    {
        $factory = new SoapClientFactory;

        $factory->create($this->wsdl());
        $factory->create($this->wsdl('PNR_v1.wsdl'));

        $this->assertEquals(2, $factory->poolSize());
    }

    public function test_flush_empties_the_pool(): void
    {
        $factory = new SoapClientFactory;
        $first = $factory->create($this->wsdl());

        $factory->flush();

        $this->assertEquals(0, $factory->poolSize());
        $this->assertNotSame($first, $factory->create($this->wsdl()));
    }

    public function test_the_pool_starts_empty(): void
    {
        $this->assertEquals(0, (new SoapClientFactory)->poolSize());
    }
}
