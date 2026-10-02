<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Client;

use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Tests\Doubles\RecordingRetryHandler;
use PHPUnit\Framework\TestCase;
use SoapFault;

class RetryHandlerTest extends TestCase
{
    public function test_a_successful_call_runs_once(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 3);
        $calls = 0;

        $result = $handler->execute(function () use (&$calls) {
            $calls++;

            return 'ok';
        });

        $this->assertEquals('ok', $result);
        $this->assertEquals(1, $calls);
        $this->assertEmpty($handler->delays);
    }

    public function test_it_retries_until_the_call_succeeds(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 4, baseDelayMs: 10);
        $calls = 0;

        $result = $handler->execute(function () use (&$calls) {
            $calls++;

            if ($calls < 3) {
                throw ConnectionException::timeout('Hotel_Sell');
            }

            return 'recovered';
        });

        $this->assertEquals('recovered', $result);
        $this->assertEquals(3, $calls);
        $this->assertEquals([10, 20], $handler->delays);
    }

    public function test_it_rethrows_the_last_failure_once_attempts_run_out(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 3, baseDelayMs: 10);
        $calls = 0;

        try {
            $handler->execute(function () use (&$calls) {
                $calls++;

                throw ConnectionException::failed('Hotel_Sell', "attempt {$calls}");
            });
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException $e) {
            $this->assertEquals(3, $calls);
            $this->assertStringContainsString('attempt 3', $e->getMessage());
            // no sleep after the final attempt
            $this->assertCount(2, $handler->delays);
        }
    }

    public function test_non_connection_exceptions_pass_straight_through(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 3, baseDelayMs: 10);
        $calls = 0;

        try {
            $handler->execute(function () use (&$calls) {
                $calls++;

                throw new SoapFaultException(new SoapFault('Client', 'business rule'));
            });
            $this->fail('Expected SoapFaultException.');
        } catch (SoapFaultException) {
            $this->assertEquals(1, $calls);
            $this->assertEmpty($handler->delays);
        }
    }

    public function test_a_disabled_handler_does_not_retry(): void
    {
        $handler = new RecordingRetryHandler(enabled: false, maxAttempts: 5, baseDelayMs: 10);
        $calls = 0;

        try {
            $handler->execute(function () use (&$calls) {
                $calls++;

                throw ConnectionException::timeout('Hotel_Sell');
            });
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException) {
            $this->assertEquals(1, $calls);
        }
    }

    public function test_a_single_attempt_configuration_does_not_retry(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 1, baseDelayMs: 10);
        $calls = 0;

        try {
            $handler->execute(function () use (&$calls) {
                $calls++;

                throw ConnectionException::timeout('Hotel_Sell');
            });
            $this->fail('Expected ConnectionException.');
        } catch (ConnectionException) {
            $this->assertEquals(1, $calls);
        }
    }

    public function test_the_delay_grows_exponentially(): void
    {
        $handler = new RecordingRetryHandler(baseDelayMs: 500, multiplier: 2.0, maxDelayMs: 5000);

        $this->assertEquals(500, $handler->calculateDelay(1));
        $this->assertEquals(1000, $handler->calculateDelay(2));
        $this->assertEquals(2000, $handler->calculateDelay(3));
        $this->assertEquals(4000, $handler->calculateDelay(4));
    }

    public function test_the_delay_is_capped(): void
    {
        $handler = new RecordingRetryHandler(baseDelayMs: 500, multiplier: 2.0, maxDelayMs: 3000);

        $this->assertEquals(3000, $handler->calculateDelay(4));
        $this->assertEquals(3000, $handler->calculateDelay(10));
    }

    public function test_it_exposes_its_configuration(): void
    {
        $handler = new RecordingRetryHandler(enabled: true, maxAttempts: 4);

        $this->assertTrue($handler->isEnabled());
        $this->assertEquals(4, $handler->getMaxAttempts());
    }
}
