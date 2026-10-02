<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Operations;

use Aldogtz\AmadeusSoap\Operations\PnrAddMultiElements;
use Carbon\Carbon;
use PHPUnit\Framework\TestCase;

class PnrAddMultiElementsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-31 17:23:00');
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    protected function retentionDate(PnrAddMultiElements $operation): string
    {
        return $operation->build()['originDestinationDetails']['itineraryInfo']['airAuxItinerary']['travelProduct']['product']['depDate'];
    }

    protected function traveler(array $extra = []): array
    {
        return ['surname' => 'DOE', 'name' => 'JOHN', 'type' => 'ADT'] + $extra;
    }

    public function test_without_a_check_out_date_the_retention_is_a_week_away(): void
    {
        $this->assertSame('070826', $this->retentionDate(new PnrAddMultiElements('create', $this->traveler())));
    }

    public function test_the_retention_follows_the_check_out_date_argument(): void
    {
        // 2026-09-01 + 7 days + 6 months
        $operation = new PnrAddMultiElements('create', $this->traveler(), checkOutDate: '2026-09-01');

        $this->assertSame('080327', $this->retentionDate($operation));
    }

    public function test_a_single_passenger_check_out_date_is_used(): void
    {
        $operation = new PnrAddMultiElements('create', $this->traveler(['check_out_date' => '2026-09-01']));

        $this->assertSame('080327', $this->retentionDate($operation));
    }

    public function test_the_first_passenger_check_out_date_is_used_for_a_list(): void
    {
        $operation = new PnrAddMultiElements('create', [
            $this->traveler(['check_out_date' => '2026-09-01']),
            ['surname' => 'DOE', 'name' => 'JANE', 'type' => 'ADT'],
        ]);

        $this->assertSame('080327', $this->retentionDate($operation));
    }

    public function test_the_argument_wins_over_the_passengers(): void
    {
        $operation = new PnrAddMultiElements('create', [$this->traveler(['check_out_date' => '2026-09-01'])], checkOutDate: '2026-10-01');

        $this->assertSame('080427', $this->retentionDate($operation));
    }

    public function test_the_retention_never_goes_past_the_configured_maximum(): void
    {
        // now + 361 days
        $operation = new PnrAddMultiElements('create', $this->traveler(), checkOutDate: '2027-06-01');

        $this->assertSame('270727', $this->retentionDate($operation));
    }
}
