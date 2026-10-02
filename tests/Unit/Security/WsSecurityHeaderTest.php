<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Security;

use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use PHPUnit\Framework\TestCase;
use SoapHeader;

class WsSecurityHeaderTest extends TestCase
{
    public function test_it_generates_a_soap_header(): void
    {
        $header = new WsSecurityHeader('testuser', 'testpass');
        $result = $header->generate();

        $this->assertInstanceOf(SoapHeader::class, $result);
        $this->assertEquals('Security', $result->name);
    }
}
