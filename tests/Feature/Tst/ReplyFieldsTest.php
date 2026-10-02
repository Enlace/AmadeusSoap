<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature\Tst;

use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelCompleteReservationDetailsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelDescriptiveInfoResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelPricingResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Tax;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Warning;
use Aldogtz\AmadeusSoap\Tests\TestCase;

/**
 * Fields an application reads to price, guarantee and record a booking
 * (BookingV2 took them with its own XPaths), parsed from real TST replies.
 */
class ReplyFieldsTest extends TestCase
{
    public function test_a_room_stay_carries_commission_cards_penalties_and_taxes(): void
    {
        $room = HotelSearchResponse::fromXml($this->tstFixture('responses/hotel-search-single.xml'))->roomStays[1];

        $this->assertSame('1KN57JU', $room->bookingCode);
        $this->assertSame('Commissionable', $room->commissionStatusType);
        $this->assertSame('AvailableForSale', $room->availabilityStatus);
        $this->assertSame(['AX', 'VI', 'CA'], $room->acceptedCardCodes);

        $this->assertCount(1, $room->cancelPenalties);
        $this->assertFalse($room->cancelPenalties[0]->nonRefundable);
        $this->assertSame('2026-08-29T18:00:00', $room->cancelPenalties[0]->absoluteDeadline);

        $this->assertEquals([new Tax(code: '17', percent: 19.0, amount: null, currencyCode: null, chargeUnit: null, type: 'Exclusive')], $room->taxes);
    }

    public function test_a_multi_search_carries_surcharges_addresses_and_provider_warnings(): void
    {
        $search = HotelSearchResponse::fromXml($this->tstFixture('responses/hotel-search-multi.xml'));

        $hotel = $search->hotels[0];
        $this->assertSame('CPMTYE71', $hotel->hotelCode);
        $this->assertSame('CROWNE PLAZA HOTELS', $hotel->chainName);
        $this->assertSame('MTY', $hotel->hotelCityCode);
        $this->assertSame("BLVD AEROPUERTO 171\nCOL. PARQUE INDUSTRIAL NEXXUS", $hotel->address?->addressLine);
        $this->assertSame('MONTERREY', $hotel->address?->cityName);
        $this->assertSame('MX', $hotel->address?->countryCode);

        // Per-night surcharges (ChargeUnit 19) of the Novotel rate
        $surcharges = array_values(array_filter(
            $search->roomStays[2]->taxes,
            fn (Tax $tax) => $tax->chargeUnit === '19',
        ));
        $this->assertSame('RTMTYNOV', $search->roomStays[2]->hotelCode);
        $this->assertSame(['3', '30'], array_map(fn (Tax $tax) => $tax->code, $surcharges));
        $this->assertSame('Inclusive', $surcharges[0]->type);

        $this->assertSame(
            ['AVL', 'CLS', 'OK', 'PE', 'PUE'],
            array_map(fn (Warning $warning) => $warning->tag, $search->warnings),
        );
        $this->assertSame('PRV.4', $search->warnings[1]->status);
    }

    public function test_merged_pages_keep_the_new_fields(): void
    {
        $page = HotelSearchResponse::fromXml($this->tstFixture('responses/hotel-search-multi.xml'));

        // Same RPHs on both pages: the second page's are renamed
        $merged = $page->mergePage($page);
        $second = $merged->hotels[count($page->hotels)];

        $this->assertNotSame($page->hotels[0]->roomStayRPH, $second->roomStayRPH);
        $this->assertSame('CROWNE PLAZA HOTELS', $second->chainName);
        $this->assertSame('MTY', $second->hotelCityCode);
        $this->assertEquals($page->hotels[0]->address, $second->address);
        $this->assertEquals($page->roomStays[2]->taxes, $merged->roomStays[count($page->roomStays) + 2]->taxes);
        $this->assertCount(2 * count($page->warnings), $merged->warnings);
    }

    public function test_pricing_carries_the_rate_category_and_the_cards_of_the_priced_rate(): void
    {
        $pricing = HotelPricingResponse::fromXml($this->tstFixture('responses/hotel-pricing.xml'));

        $this->assertSame('1KN57JU', $pricing->bookingCode);
        $this->assertSame('Converted:BAR:P', $pricing->ratePlanCategory);
        $this->assertSame(['AX', 'VI', 'CA'], $pricing->acceptedCardCodes);
        // Priced in the property's currency
        $this->assertSame([], $pricing->currencyConversions);
    }

    public function test_descriptive_info_reads_the_contact_address_name_and_policy_times(): void
    {
        $hotel = HotelDescriptiveInfoResponse::fromXml($this->tstFixture('responses/hotel-descriptive-info.xml'))->hotel();

        $this->assertSame('STAYBRIDGE SUITES SAN PEDRO', $hotel->hotelName);
        $this->assertSame('YZ', $hotel->chainCode);
        $this->assertSame('15:00:00', $hotel->checkInTime);
        $this->assertSame('12:00:00', $hotel->checkOutTime);

        $this->assertCount(1, $hotel->addresses);
        $this->assertSame('7', $hotel->addresses[0]->useType);
        $this->assertSame('CALZADA SAN PEDRO 103', $hotel->addresses[0]->addressLine);
        $this->assertSame('MONTERREY', $hotel->addresses[0]->cityName);
        $this->assertSame('MX', $hotel->addresses[0]->countryCode);

        // The reply has no HotelInfo/Address: the physical address stands in
        $this->assertEquals($hotel->addresses[0], $hotel->infoAddress);
    }

    public function test_a_pnr_segment_carries_its_dates_rate_and_principal_guest(): void
    {
        $pnr = AddMultiElementsResponse::fromXml($this->tstFixture('responses/pnr-end.xml'));
        $segment = $pnr->segments[0];

        $this->assertSame('2026-08-30', $segment->start);
        $this->assertSame('2026-08-31', $segment->end);
        $this->assertSame('57J', $segment->ratePlanCode);

        $principal = $pnr->travelerByReference($segment->passengerReference);
        $this->assertSame('TEST', $principal?->firstName);
        $this->assertSame('TRAVELER', $principal?->surname);
        $this->assertNull($pnr->travelerByReference('99'));
    }

    public function test_reservation_tax_dates_are_iso_dates(): void
    {
        $details = HotelCompleteReservationDetailsResponse::fromXml($this->tstFixture('responses/hotel-complete-reservation-details.xml'));

        // The reply says <month>8</month>
        $this->assertSame('2026-08-30', $details->taxes[0]->beginDate);
        $this->assertSame('2026-08-31', $details->taxes[0]->endDate);
    }
}
