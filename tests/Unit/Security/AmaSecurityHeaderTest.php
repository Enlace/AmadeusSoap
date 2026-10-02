<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Security;

use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use PHPUnit\Framework\TestCase;
use SoapHeader;

class AmaSecurityHeaderTest extends TestCase
{
    public function test_it_generates_a_soap_header_with_office_id(): void
    {
        $header = new AmaSecurityHeader('MTYOF01');
        $result = $header->generate();

        $this->assertInstanceOf(SoapHeader::class, $result);
        $this->assertEquals('AMA_SecurityHostedUser', $result->name);
        $this->assertEquals('MTYOF01', $result->data['UserID']['PseudoCityCode']);
    }
}
