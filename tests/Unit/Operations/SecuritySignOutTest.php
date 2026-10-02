<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Operations\SecuritySignOut;
use PHPUnit\Framework\TestCase;

class SecuritySignOutTest extends TestCase
{
    public function test_it_returns_correct_operation_name(): void
    {
        $operation = new SecuritySignOut;

        $this->assertEquals('Security_SignOut', $operation->getOperationName());
    }

    public function test_it_builds_empty_body(): void
    {
        $operation = new SecuritySignOut;

        $this->assertEmpty($operation->build());
    }
}
