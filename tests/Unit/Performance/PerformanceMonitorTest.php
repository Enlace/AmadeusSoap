<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Performance;

use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationFailed;
use Aldogtz\AmadeusSoap\Performance\PerformanceMonitor;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class PerformanceMonitorTest extends TestCase
{
    protected function setUp(): void
    {
        Carbon::setTestNow('2026-10-01 10:30:00');
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
    }

    protected function makeMonitor(int $storeHours = 24, int $maxSamplesPerHour = 1000): PerformanceMonitor
    {
        return new PerformanceMonitor(new Repository(new ArrayStore), $storeHours, $maxSamplesPerHour);
    }

    public function test_metrics_are_zero_without_samples(): void
    {
        $metrics = $this->makeMonitor()->getMetrics('Hotel_Sell');

        $this->assertSame(0, $metrics['count']);
        $this->assertSame(0.0, $metrics['p99_duration_ms']);
        $this->assertSame(0.0, $metrics['success_rate']);
    }

    public function test_it_aggregates_durations_and_success_rate(): void
    {
        $monitor = $this->makeMonitor();

        foreach ([100, 200, 300, 400] as $duration) {
            $monitor->record('Hotel_Sell', $duration, true);
        }
        $monitor->record('Hotel_Sell', 1000, false);

        $metrics = $monitor->getMetrics('Hotel_Sell');

        $this->assertSame(5, $metrics['count']);
        $this->assertSame(400.0, $metrics['avg_duration_ms']);
        $this->assertSame(100.0, $metrics['min_duration_ms']);
        $this->assertSame(1000.0, $metrics['max_duration_ms']);
        $this->assertSame(1000.0, $metrics['p95_duration_ms']);
        $this->assertSame(80.0, $metrics['success_rate']);
    }

    public function test_percentiles_use_nearest_rank(): void
    {
        $monitor = $this->makeMonitor();

        // A single sample used to read past the end of the list
        $monitor->record('Security_SignOut', 42, true);
        $this->assertSame(42.0, $monitor->getMetrics('Security_SignOut')['p99_duration_ms']);

        foreach (range(1, 100) as $duration) {
            $monitor->record('Hotel_MultiSingleAvailability', $duration, true);
        }

        $metrics = $monitor->getMetrics('Hotel_MultiSingleAvailability');
        $this->assertSame(95.0, $metrics['p95_duration_ms']);
        $this->assertSame(99.0, $metrics['p99_duration_ms']);
    }

    public function test_it_keeps_only_the_latest_samples_per_hour(): void
    {
        $monitor = $this->makeMonitor(maxSamplesPerHour: 3);

        foreach ([1, 2, 3, 4, 5] as $duration) {
            $monitor->record('Hotel_Sell', $duration, true);
        }

        $metrics = $monitor->getMetrics('Hotel_Sell');
        $this->assertSame(3, $metrics['count']);
        $this->assertSame(3.0, $metrics['min_duration_ms']);
    }

    public function test_the_window_covers_the_requested_hours_capped_at_store_hours(): void
    {
        $monitor = $this->makeMonitor(storeHours: 2);

        Carbon::setTestNow('2026-10-01 07:10:00');
        $monitor->record('Hotel_Sell', 10, true);
        Carbon::setTestNow('2026-10-01 09:10:00');
        $monitor->record('Hotel_Sell', 20, true);
        Carbon::setTestNow('2026-10-01 10:10:00');
        $monitor->record('Hotel_Sell', 30, true);

        $this->assertSame(1, $monitor->getMetrics('Hotel_Sell', 1)['count']);
        $this->assertSame(2, $monitor->getMetrics('Hotel_Sell', 2)['count']);
        $this->assertSame(2, $monitor->getMetrics('Hotel_Sell', 24)['count']);
    }

    public function test_it_records_operation_events(): void
    {
        $monitor = $this->makeMonitor();
        $events = new Dispatcher;
        $monitor->subscribe($events);

        $events->dispatch(new OperationCompleted('Hotel_Sell', true, 10.0, 10.25));
        $events->dispatch(new OperationFailed('Hotel_Sell', new RuntimeException('timeout'), 10.0, 10.5));

        $metrics = $monitor->getMetrics('Hotel_Sell');
        $this->assertSame(2, $metrics['count']);
        $this->assertSame(250.0, $metrics['min_duration_ms']);
        $this->assertSame(500.0, $metrics['max_duration_ms']);
        $this->assertSame(50.0, $metrics['success_rate']);
    }
}
