<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Wsdl;

use Aldogtz\AmadeusSoap\Exceptions\OperationNotFoundException;
use Aldogtz\AmadeusSoap\Wsdl\Exceptions\InvalidWsdlFileException;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use Aldogtz\AmadeusSoap\Wsdl\OperationRegistry;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use PHPUnit\Framework\TestCase;

class WsdlManagerTest extends TestCase
{
    protected function wsdlPath(): string
    {
        return dirname(__DIR__, 2).'/Fixtures/wsdl';
    }

    protected function manager(): WsdlManager
    {
        return new WsdlManager($this->wsdlPath());
    }

    protected function metadata(string $operation): OperationMetadata
    {
        return $this->manager()->getRegistry()->get($operation);
    }

    public function test_it_registers_every_operation_found_in_the_wsdl_directory(): void
    {
        $operations = array_keys($this->manager()->getRegistry()->all());

        sort($operations);

        $this->assertEquals([
            'Hotel_DescriptiveInfo',
            'Hotel_MultiSingleAvailability',
            'PNR_Retrieve',
        ], $operations);
    }

    public function test_it_extracts_full_metadata_for_a_self_contained_wsdl(): void
    {
        $metadata = $this->metadata('Hotel_MultiSingleAvailability');

        $this->assertEquals('Hotel_MultiSingleAvailability', $metadata->name);
        $this->assertEquals('11.0', $metadata->version);
        $this->assertEquals('Hotel_MultiSingleAvailability_11_0', $metadata->inputMessageName);
        $this->assertEquals('Hotel_MultiSingleAvailabilityReply_11_0', $metadata->outputMessageName);
        $this->assertEquals('http://webservices.amadeus.com/HOTMSAR_11_0', $metadata->soapAction);
        $this->assertEquals('https://nodeD1.test.webservices.amadeus.com/1ASIWTEST', $metadata->serviceEndpoint);
        $this->assertEquals('Hotel_MultiSingleAvailability', $metadata->rootElement);
        $this->assertEquals('Hotel_MultiSingleAvailabilityReply', $metadata->responseRootElement);
        $this->assertEquals('http://xml.amadeus.com/HOTMSAR_11_0', $metadata->responseNamespace);
        $this->assertEquals($this->wsdlPath().'/Hotel_v1.wsdl', $metadata->wsdlPath);
    }

    public function test_operations_in_the_same_wsdl_get_their_own_namespaces_and_versions(): void
    {
        $metadata = $this->metadata('Hotel_DescriptiveInfo');

        $this->assertEquals('4.0', $metadata->version);
        $this->assertEquals('Hotel_DescriptiveInfoReply', $metadata->responseRootElement);
        $this->assertEquals('http://xml.amadeus.com/HOTDIR_04_0', $metadata->responseNamespace);
        $this->assertEquals('http://webservices.amadeus.com/HOTDIR_04_0', $metadata->soapAction);
    }

    public function test_the_reply_message_does_not_shadow_the_request_message_version(): void
    {
        // Both Hotel_MultiSingleAvailability_11_0 and
        // Hotel_MultiSingleAvailabilityReply_11_0 exist; the version lookup
        // must pick the request message, not whichever comes first.
        $this->assertEquals('11.0', $this->metadata('Hotel_MultiSingleAvailability')->version);
        $this->assertEquals('4.0', $this->metadata('Hotel_DescriptiveInfo')->version);
    }

    public function test_it_resolves_operations_declared_in_an_imported_wsdl(): void
    {
        $metadata = $this->metadata('PNR_Retrieve');

        $this->assertEquals('11.3', $metadata->version);
        $this->assertEquals('PNR_Retrieve_11_3', $metadata->inputMessageName);
        $this->assertEquals('PNR_RetrieveReply_11_3', $metadata->outputMessageName);
        // soapAction and endpoint come from the base WSDL, not the import
        $this->assertEquals('http://webservices.amadeus.com/PNRRET_11_3', $metadata->soapAction);
        $this->assertEquals('https://nodeD2.test.webservices.amadeus.com/1ASIWTEST', $metadata->serviceEndpoint);
        // rootElement/responseNamespace require the import to be merged into the base DOM
        $this->assertEquals('PNR_Retrieve', $metadata->rootElement);
        $this->assertEquals('PNR_Reply', $metadata->responseRootElement);
        $this->assertEquals('http://xml.amadeus.com/PNRRET_11_3', $metadata->responseNamespace);
    }

    public function test_imported_operations_resolve_identically_across_instances(): void
    {
        // Regression: import merging used to be tracked in a static, so any
        // WsdlManager built after the first one in the same process resolved
        // an empty rootElement for imported operations.
        $first = $this->manager()->getRegistry()->get('PNR_Retrieve');
        $second = $this->manager()->getRegistry()->get('PNR_Retrieve');

        $this->assertEquals($first->rootElement, $second->rootElement);
        $this->assertEquals($first->responseRootElement, $second->responseRootElement);
        $this->assertEquals($first->responseNamespace, $second->responseNamespace);
        $this->assertNotEmpty($second->rootElement);
    }

    public function test_it_records_the_wsdl_id_and_path_of_each_file(): void
    {
        $manager = $this->manager();
        $wsdlIds = $manager->getWsdlIds();

        $this->assertCount(2, $wsdlIds);
        $this->assertEqualsCanonicalizing(
            [$this->wsdlPath().'/Hotel_v1.wsdl', $this->wsdlPath().'/PNR_v1.wsdl'],
            array_values($wsdlIds),
        );

        $hotelId = $manager->getRegistry()->get('Hotel_MultiSingleAvailability')->wsdlId;
        $pnrId = $manager->getRegistry()->get('PNR_Retrieve')->wsdlId;

        $this->assertArrayHasKey($hotelId, $wsdlIds);
        $this->assertArrayHasKey($pnrId, $wsdlIds);
        $this->assertNotEquals($hotelId, $pnrId);
    }

    public function test_the_imported_file_is_not_registered_as_a_root_wsdl(): void
    {
        // imports/ lives below the scanned directory; scandir only walks the top level
        foreach ($this->manager()->getWsdlIds() as $path) {
            $this->assertStringNotContainsString('imports', $path);
        }
    }

    public function test_construction_does_not_read_the_filesystem(): void
    {
        // Lazy loading: an unusable path must not blow up until the registry
        // is actually needed.
        $manager = new WsdlManager('/definitely/not/a/real/path');

        $this->expectException(InvalidWsdlFileException::class);

        $manager->getRegistry();
    }

    public function test_a_missing_wsdl_directory_reports_the_configured_path(): void
    {
        try {
            (new WsdlManager('/definitely/not/a/real/path'))->getRegistry();
            $this->fail('Expected InvalidWsdlFileException.');
        } catch (InvalidWsdlFileException $e) {
            $this->assertStringContainsString('/definitely/not/a/real/path', $e->getMessage());
            $this->assertStringContainsString('wsdl_path', $e->getMessage());
        }
    }

    public function test_the_registry_is_built_once_and_reused(): void
    {
        $manager = $this->manager();

        $this->assertInstanceOf(OperationRegistry::class, $manager->getRegistry());
        $this->assertSame($manager->getRegistry(), $manager->getRegistry());
    }

    public function test_an_unknown_operation_throws(): void
    {
        $this->expectException(OperationNotFoundException::class);
        $this->expectExceptionMessage('Hotel_Nonexistent');

        $this->manager()->getRegistry()->get('Hotel_Nonexistent');
    }
}
