<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\ErrorHandling;

use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use PHPUnit\Framework\TestCase;

class ConnectionExceptionTest extends TestCase
{
    public function test_timeout_factory(): void
    {
        $exception = ConnectionException::timeout('Hotel_MultiSingleAvailability');

        $this->assertStringContainsString('timeout', strtolower($exception->getMessage()));
        $this->assertStringContainsString('Hotel_MultiSingleAvailability', $exception->getMessage());
    }

    public function test_ssl_error_factory(): void
    {
        $exception = ConnectionException::sslError('Hotel_Sell', 'certificate expired');

        $this->assertStringContainsString('SSL', $exception->getMessage());
        $this->assertStringContainsString('certificate expired', $exception->getMessage());
        $this->assertStringContainsString('Hotel_Sell', $exception->getMessage());
    }

    public function test_failed_factory(): void
    {
        $exception = ConnectionException::failed('PNR_Retrieve', 'DNS resolution failed');

        $this->assertStringContainsString('failed', strtolower($exception->getMessage()));
        $this->assertStringContainsString('DNS resolution failed', $exception->getMessage());
    }

    public function test_with_transport_context(): void
    {
        $exception = ConnectionException::timeout('Hotel_Sell')
            ->withTransportContext('<request/>', '<response/>');

        $this->assertEquals('<request/>', $exception->getLastRequest());
        $this->assertEquals('<response/>', $exception->getLastResponse());
    }

    public function test_without_transport_context(): void
    {
        $exception = ConnectionException::timeout('Hotel_Sell');

        $this->assertNull($exception->getLastRequest());
        $this->assertNull($exception->getLastResponse());
    }

    public function test_preserves_previous_exception(): void
    {
        $previous = new \RuntimeException('original error');
        $exception = ConnectionException::timeout('Hotel_Sell', $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }
}
