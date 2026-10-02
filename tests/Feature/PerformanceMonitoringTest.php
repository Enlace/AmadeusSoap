<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationFailed;
use Aldogtz\AmadeusSoap\Performance\PerformanceMonitor;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Illuminate\Contracts\Events\Dispatcher;
use Orchestra\Testbench\Attributes\DefineEnvironment;

class PerformanceMonitoringTest extends TestCase
{
    protected function enableMonitoring($app): void
    {
        $app['config']->set('amadeus-soap.monitoring.enabled', true);
    }

    #[DefineEnvironment('enableMonitoring')]
    public function test_every_soap_call_is_recorded(): void
    {
        $this->fakeAmadeus('hotel-search-multi', 'hotel-search-multi');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $params = ['hotel_city_code' => 'MTY', 'start' => '2026-08-30', 'end' => '2026-08-31'];
        $amadeus->hotelSearch('multi', $params);
        $amadeus->hotelSearch('multi', $params);

        $metrics = $this->app->make(PerformanceMonitor::class)->getMetrics('Hotel_MultiSingleAvailability');

        $this->assertSame(2, $metrics['count']);
        $this->assertSame(100.0, $metrics['success_rate']);
        $this->assertGreaterThan(0, $metrics['max_duration_ms']);
    }

    #[DefineEnvironment('enableMonitoring')]
    public function test_the_monitor_listens_to_operation_events(): void
    {
        $events = $this->app->make(Dispatcher::class);

        $this->assertTrue($events->hasListeners(OperationCompleted::class));
        $this->assertTrue($events->hasListeners(OperationFailed::class));
    }

    public function test_nothing_listens_when_monitoring_is_disabled(): void
    {
        $events = $this->app->make(Dispatcher::class);

        $this->assertFalse($events->hasListeners(OperationCompleted::class));
        $this->assertFalse($events->hasListeners(OperationFailed::class));
    }
}
