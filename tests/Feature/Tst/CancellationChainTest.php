<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\PnrCancelResponse;
use Aldogtz\AmadeusSoap\Tests\TestCase;

/**
 * The second half of the chain, from the end transaction to the
 * cancellation, against the requests TST accepted for a complete booking
 * (PNR TST003, hotel segment 2).
 */
class CancellationChainTest extends TestCase
{
    public function test_the_end_transaction_sends_the_request_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('hotel-search-single', 'pnr-end');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->hotelSearch('single', ['hotel_code' => 'YZMTY045', 'start' => '2026-08-30', 'end' => '2026-08-31', 'rate_code' => []]);
        $amadeus->addMultiElements('end');

        $this->assertSoapBodyMatchesFixture('pnr-end', $client->requests[1]['xml']);
    }

    public function test_retrieve_and_details_send_the_requests_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('pnr-retrieve', 'hotel-complete-reservation-details');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->pnrRetrieve('TST003');
        $amadeus->hotelCompleteReservationDetails(['pnr_number' => 'TST003', 'segment_number' => '2']);

        $this->assertSoapBodyMatchesFixture('pnr-retrieve', $client->requests[0]['xml']);
        $this->assertSoapBodyMatchesFixture('hotel-complete-reservation-details', $client->requests[1]['xml']);
    }

    public function test_cancelling_the_segment_sends_the_requests_amadeus_accepted(): void
    {
        $client = $this->fakeAmadeus('pnr-retrieve', 'pnr-cancel', 'pnr-cancel-end');
        $amadeus = $this->app->make(AmadeusSoap::class);

        $amadeus->pnrRetrieve('TST003');
        $cancel = $amadeus->pnrCancel('2');
        $end = $amadeus->addMultiElements('cancel');

        $this->assertSoapBodyMatchesFixture('pnr-cancel', $client->requests[1]['xml']);
        $this->assertSoapBodyMatchesFixture('pnr-cancel-end', $client->requests[2]['xml']);

        $this->assertInstanceOf(PnrCancelResponse::class, $cancel);
        $this->assertFalse($cancel->hasErrors);
        $this->assertInstanceOf(AddMultiElementsResponse::class, $end);
        $this->assertFalse($end->hasErrors);
    }

    public function test_the_committed_cancellation_no_longer_lists_the_segment(): void
    {
        $cancelled = AddMultiElementsResponse::fromXml($this->tstFixture('responses/pnr-cancel-end.xml'));
        $beforeCommit = AddMultiElementsResponse::fromXml($this->tstFixture('responses/pnr-cancel.xml'));

        $this->assertSame('TST003', $cancelled->pnrNumber);
        $this->assertTrue($cancelled->isSegmentDeleted('2'));
        // PNR_Cancel alone does not commit: the segment is still listed
        $this->assertFalse($beforeCommit->isSegmentDeleted('2'));
    }
}
