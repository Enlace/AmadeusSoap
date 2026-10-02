<?php

namespace Aldogtz\AmadeusSoap\Performance;

use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationFailed;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Carbon;

/**
 * Records response times and success rates of SOAP operations.
 *
 * Fed by the OperationCompleted / OperationFailed events (registered as an
 * event subscriber when monitoring is enabled). Samples are bucketed per
 * operation and hour in the cache store.
 *
 * Buckets are updated with read-modify-write, so concurrent requests may
 * drop a sample now and then: treat the numbers as approximate.
 */
class PerformanceMonitor
{
    public function __construct(
        protected Repository $store,
        protected int $storeHours = 24,
        protected int $maxSamplesPerHour = 1000,
        protected string $prefix = 'amadeus_metrics',
    ) {}

    /**
     * Register the listeners (Laravel event subscriber).
     *
     * Listeners run synchronously inside the SOAP call: a store failure is
     * reported and swallowed, so it can never fail a call Amadeus already
     * processed (e.g. a sell that did book the room).
     */
    public function subscribe(Dispatcher $events): void
    {
        $events->listen(OperationCompleted::class, function (OperationCompleted $event) {
            rescue(fn () => $this->record($event->operation, $event->durationMs, true));
        });

        $events->listen(OperationFailed::class, function (OperationFailed $event) {
            rescue(fn () => $this->record($event->operation, $event->durationMs, false));
        });
    }

    public function record(string $operation, float $durationMs, bool $success): void
    {
        $now = Carbon::now();
        $key = $this->bucketKey($operation, $now);

        $samples = $this->store->get($key, []);
        $samples[] = ['duration_ms' => round($durationMs, 2), 'success' => $success];

        if (count($samples) > $this->maxSamplesPerHour) {
            $samples = array_slice($samples, -$this->maxSamplesPerHour);
        }

        $this->store->put($key, $samples, $now->copy()->addHours($this->storeHours));
    }

    /**
     * Aggregated metrics for an operation over the last N hours (capped at store_hours).
     *
     * @return array{count: int, avg_duration_ms: float, min_duration_ms: float, max_duration_ms: float, p95_duration_ms: float, p99_duration_ms: float, success_rate: float}
     */
    public function getMetrics(string $operation, int $hours = 1): array
    {
        $hours = max(1, min($hours, $this->storeHours));
        $now = Carbon::now();
        $samples = [];

        for ($i = 0; $i < $hours; $i++) {
            $samples = array_merge($samples, $this->store->get($this->bucketKey($operation, $now->copy()->subHours($i)), []));
        }

        if ($samples === []) {
            return [
                'count' => 0,
                'avg_duration_ms' => 0.0,
                'min_duration_ms' => 0.0,
                'max_duration_ms' => 0.0,
                'p95_duration_ms' => 0.0,
                'p99_duration_ms' => 0.0,
                'success_rate' => 0.0,
            ];
        }

        $durations = array_map('floatval', array_column($samples, 'duration_ms'));
        sort($durations);
        $successes = count(array_filter($samples, fn (array $sample) => $sample['success']));

        return [
            'count' => count($samples),
            'avg_duration_ms' => round(array_sum($durations) / count($durations), 2),
            'min_duration_ms' => $durations[0],
            'max_duration_ms' => $durations[count($durations) - 1],
            'p95_duration_ms' => $this->percentile($durations, 95),
            'p99_duration_ms' => $this->percentile($durations, 99),
            'success_rate' => round($successes / count($samples) * 100, 2),
        ];
    }

    /**
     * Nearest-rank percentile of an ascending, non-empty list.
     *
     * @param  float[]  $sorted
     */
    protected function percentile(array $sorted, float $percentile): float
    {
        $rank = (int) ceil($percentile / 100 * count($sorted));

        return $sorted[max(0, $rank - 1)];
    }

    protected function bucketKey(string $operation, Carbon $time): string
    {
        return sprintf('%s:%s:%s', $this->prefix, $operation, $time->format('Y-m-d-H'));
    }
}
