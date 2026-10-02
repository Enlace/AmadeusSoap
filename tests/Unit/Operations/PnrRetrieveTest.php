<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Operations\PnrRetrieve;
use PHPUnit\Framework\TestCase;

class PnrRetrieveTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $params = PnrRetrieveParams::fromArray(['pnrNumber' => 'ABC123']);
        $operation = new PnrRetrieve($params);

        $this->assertEquals('PNR_Retrieve', $operation->getOperationName());
    }

    public function test_it_builds_retrieve_body(): void
    {
        $params = PnrRetrieveParams::fromArray(['pnrNumber' => 'XYZ789']);
        $operation = new PnrRetrieve($params);
        $body = $operation->build();

        $this->assertArrayHasKey('retrievalFacts', $body);
        $this->assertEquals('2', $body['retrievalFacts']['retrieve']['type']);
        $this->assertEquals('XYZ789', $body['retrievalFacts']['reservationOrProfileIdentifier']['reservation']['controlNumber']);
    }
}
