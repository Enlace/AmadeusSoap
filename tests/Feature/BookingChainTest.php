<?php

namespace Aldogtz\AmadeusSoap\Tests\Feature;

use Aldogtz\AmadeusSoap\AmadeusSoap;
use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationStarting;
use Aldogtz\AmadeusSoap\Headers\HeaderBuilder;
use Aldogtz\AmadeusSoap\Logging\SoapLogger;
use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Tests\Doubles\FakeTransport;
use Aldogtz\AmadeusSoap\Tests\TestCase;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use Illuminate\Support\Facades\Event;

/**
 * Drives the whole booking flow through AmadeusSoap with a fake transport and
 * responses shaped like real Amadeus replies.
 *
 * This is the orchestration nothing else covers: which operations run, whether
 * each is stateful, how the session advances between them, and whether the
 * values one step returns are usable as input to the next.
 */
class BookingChainTest extends TestCase
{
    protected FakeTransport $transport;

    protected ArraySessionStore $store;

    protected SessionManager $sessionManager;

    protected AmadeusSoap $amadeus;

    protected function setUp(): void
    {
        parent::setUp();

        $this->transport = (new FakeTransport)
            ->reply('Hotel_MultiSingleAvailability', 'hotel_search_multi_rate.xml')
            ->reply('Hotel_EnhancedPricing', 'hotel_pricing.xml')
            // PNR_AddMultiElements runs three times in a full chain:
            // create, end, then cancel-confirm.
            ->reply('PNR_AddMultiElements', 'pnr_create.xml')
            ->reply('PNR_AddMultiElements', 'pnr_end.xml')
            ->reply('PNR_AddMultiElements', 'pnr_cancel.xml')
            ->reply('Hotel_Sell', 'hotel_sell.xml')
            ->reply('PNR_Retrieve', 'pnr_retrieve.xml')
            ->reply('PNR_Cancel', 'pnr_cancel.xml')
            ->reply('Security_SignOut', 'security_signout.xml');

        $this->store = new ArraySessionStore;
        $this->sessionManager = new SessionManager(
            store: $this->store,
            keyResolver: fn () => 'chain-test',
            statelessOperations: ['Hotel_DescriptiveInfo'],
        );

        $this->amadeus = $this->amadeusWith($this->transport);
    }

    /**
     * Build AmadeusSoap over a given transport, sharing this test's session
     * manager so session assertions hold across swapped transports.
     */
    protected function amadeusWith(FakeTransport $transport): AmadeusSoap
    {
        return new AmadeusSoap(
            wsdlManager: new WsdlManager(dirname(__DIR__).'/Fixtures/wsdl-full'),
            sessionManager: $this->sessionManager,
            transport: $transport,
            logger: new SoapLogger(enabled: false),
            config: [
                'retention' => ['months' => 6, 'city_code' => 'MTY', 'max_days' => 361],
                'contact_email' => 'test@example.test',
            ],
        );
    }

    protected function searchParams(): array
    {
        return [
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'hotel_city_code' => 'MTY',
            'guest_count' => '1',
            'quantity' => '1',
        ];
    }

    protected function passenger(): array
    {
        return ['surname' => 'TEST', 'name' => 'TRAVELER', 'type' => 'ADT'];
    }

    // -----------------------------------------------------------------
    // The chain, start to finish
    // -----------------------------------------------------------------

    public function test_the_full_booking_chain_runs_in_order(): void
    {
        $search = $this->amadeus->hotelSearch('multi', $this->searchParams());
        $hotel = $search->hotels[0];
        $rate = $hotel->roomStays($search->roomStays)[0];

        $this->amadeus->hotelPricing([
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'hotel_code' => $hotel->hotelCode,
            'rate_plan_code' => $rate->ratePlanCode,
            'booking_code' => $rate->bookingCode,
            'room_type_code' => $rate->roomTypeCode,
            'quantity' => '1',
            'guest_count' => '1',
        ]);

        $create = $this->amadeus->addMultiElements('create', $this->passenger());

        $this->amadeus->hotelSell([
            'travelAgentRef' => $create->travelAgentRef,
            'chainCode' => $hotel->chainCode,
            'cityCode' => 'MTY',
            'hotelCode' => $hotel->hotelCode,
            'bookingCode' => $rate->bookingCode,
            'paymentType' => 'CC',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'TRAVELER',
            'passengerReference' => ['type' => 'BHO', 'value' => $create->travelers[0]->referenceNumber],
        ]);

        $this->amadeus->addMultiElements('end', $this->passenger());
        $this->amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);
        $this->amadeus->pnrCancel(['segmentNumber' => '2']);
        $this->amadeus->signOut();

        $this->assertEquals([
            'Hotel_MultiSingleAvailability',
            'Hotel_EnhancedPricing',
            'PNR_AddMultiElements',
            'Hotel_Sell',
            'PNR_AddMultiElements',
            // PNR_Retrieve starts a new session: the booking one is signed out
            // first instead of being left open on Amadeus
            'Security_SignOut',
            'PNR_Retrieve',
            'PNR_Cancel',
            'Security_SignOut',
        ], $this->transport->operations());
    }

    public function test_values_flow_from_each_step_into_the_next(): void
    {
        $search = $this->amadeus->hotelSearch('multi', $this->searchParams());
        $hotel = $search->hotels[0];
        $rate = $hotel->roomStays($search->roomStays)[0];

        // Search yields the three codes pricing requires
        $this->assertEquals('CITST001', $hotel->hotelCode);
        $this->assertEquals('ENF', $rate->ratePlanCode);
        $this->assertEquals('BCODE001', $rate->bookingCode);
        $this->assertEquals('N1D', $rate->roomTypeCode);

        $pricing = $this->amadeus->hotelPricing([
            'start' => '2027-05-19',
            'end' => '2027-05-20',
            'hotel_code' => $hotel->hotelCode,
            'rate_plan_code' => $rate->ratePlanCode,
            'booking_code' => $rate->bookingCode,
            'room_type_code' => $rate->roomTypeCode,
            'quantity' => '1',
            'guest_count' => '1',
        ]);

        $this->assertFalse($pricing->hasErrors);
        $this->assertEquals('ENF', $pricing->ratePlanCode);
        $this->assertEquals('BCODE001', $pricing->bookingCode);

        // PNR create yields the references hotelSell needs
        $create = $this->amadeus->addMultiElements('create', $this->passenger());

        $this->assertFalse($create->hasErrors);
        $this->assertEquals('1', $create->travelAgentRef);
        $this->assertCount(1, $create->travelers);
        $this->assertEquals('2', $create->travelers[0]->referenceNumber);
        $this->assertEquals('TRAVELER', $create->travelers[0]->firstName);

        // Sell yields the reservation number and hotel confirmation
        $sell = $this->amadeus->hotelSell([
            'travelAgentRef' => $create->travelAgentRef,
            'chainCode' => $hotel->chainCode,
            'cityCode' => 'MTY',
            'hotelCode' => $hotel->hotelCode,
            'bookingCode' => $rate->bookingCode,
            'paymentType' => 'CC',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'TRAVELER',
            'passengerReference' => ['type' => 'BHO', 'value' => $create->travelers[0]->referenceNumber],
        ]);

        $this->assertFalse($sell->hasErrors);
        $this->assertEquals('99999999', $sell->bookingReference);
        // The hotel's confirmation: the same number PNR_Reply reports for the
        // segment below. The booking code is only the echo of the request.
        $this->assertEquals('99999999', $sell->confirmationNumber);
        $this->assertEquals('BCODE001', $sell->roomResults[0]->bookingCode);
        $this->assertCount(1, $sell->roomResults);
        $this->assertEquals('CIMTY001', $sell->roomResults[0]->hotelCode);

        // End transaction yields the record locator
        $end = $this->amadeus->addMultiElements('end', $this->passenger());

        $this->assertFalse($end->hasErrors);
        $this->assertEquals('TEST01', $end->pnrNumber);
        $this->assertEquals('ENF', $end->ratePlanCode);
        $this->assertCount(1, $end->segments);
        $this->assertEquals('2', $end->segments[0]->segmentNumber);
        $this->assertEquals('99999999', $end->segments[0]->confirmationNumber);
        $this->assertEquals('CIMTY001', $end->segments[0]->hotelCode);
    }

    public function test_the_reservation_can_be_retrieved_and_cancelled(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());

        $retrieve = $this->amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);

        $this->assertFalse($retrieve->hasErrors);
        $this->assertEquals('TEST01', $retrieve->pnrNumber);
        $this->assertCount(1, $retrieve->segments);
        $this->assertEquals('2', $retrieve->segments[0]->segmentNumber);

        $cancel = $this->amadeus->pnrCancel(['segmentNumber' => '2']);

        $this->assertFalse($cancel->hasErrors);

        // The cancel reply no longer lists the HHL segment
        $confirm = $this->amadeus->addMultiElements('cancel', []);
        $this->assertTrue($confirm->isSegmentDeleted('2'));
    }

    // -----------------------------------------------------------------
    // Cancellation, in the order the live flow requires
    // -----------------------------------------------------------------

    public function test_the_cancellation_sequence_runs_in_order(): void
    {
        $this->transport = (new FakeTransport)
            ->reply('PNR_Retrieve', 'pnr_retrieve.xml')
            ->reply('Hotel_CompleteReservationDetails', 'hotel_complete_reservation_details.xml')
            ->reply('PNR_Cancel', 'pnr_cancel.xml')
            ->reply('PNR_AddMultiElements', 'pnr_cancel.xml')
            ->reply('Security_SignOut', 'security_signout.xml');

        $amadeus = $this->amadeusWith($this->transport);

        $retrieve = $amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);
        $segment = $retrieve->segments[0]->segmentNumber;

        $amadeus->hotelCompleteReservationDetails([
            'pnrNumber' => 'TEST01',
            'segmentNumber' => $segment,
        ]);
        $amadeus->pnrCancel(['segmentNumber' => $segment]);
        $amadeus->addMultiElements('cancel', []);
        $amadeus->signOut();

        $this->assertEquals([
            'PNR_Retrieve',
            'Hotel_CompleteReservationDetails',
            'PNR_Cancel',
            'PNR_AddMultiElements',
            'Security_SignOut',
        ], $this->transport->operations());
    }

    public function test_the_segment_to_cancel_comes_from_the_hhl_segment(): void
    {
        // The PNR also holds an RU retention segment, so the number cannot be
        // assumed to be '1' — pnrCancel takes the HHL segment's ST reference.
        $this->transport = (new FakeTransport)
            ->reply('PNR_Retrieve', 'pnr_retrieve.xml')
            ->reply('PNR_Cancel', 'pnr_cancel.xml');

        $amadeus = $this->amadeusWith($this->transport);

        $retrieve = $amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);

        $this->assertCount(1, $retrieve->segments, 'only HHL segments are listed');
        $this->assertEquals('2', $retrieve->segments[0]->segmentNumber);

        $amadeus->pnrCancel(['segmentNumber' => $retrieve->segments[0]->segmentNumber]);

        $body = $this->transport->callTo('PNR_Cancel')['body'];
        $this->assertStringContainsString('<identifier>ST</identifier>', $body);
        $this->assertStringContainsString('<number>2</number>', $body);
    }

    public function test_cancelling_several_segments_at_once(): void
    {
        $this->transport = (new FakeTransport)->reply('PNR_Cancel', 'pnr_cancel.xml');

        $this->amadeusWith($this->transport)->pnrCancel(['segmentNumber' => ['2', '3']]);

        $body = $this->transport->callTo('PNR_Cancel')['body'];

        $this->assertEquals(2, substr_count($body, '<identifier>ST</identifier>'));
        $this->assertStringContainsString('<number>2</number>', $body);
        $this->assertStringContainsString('<number>3</number>', $body);
    }

    public function test_reservation_details_read_the_cancellation_policy(): void
    {
        $this->transport = (new FakeTransport)
            ->reply('Hotel_CompleteReservationDetails', 'hotel_complete_reservation_details.xml');

        $details = $this->amadeusWith($this->transport)->hotelCompleteReservationDetails([
            'pnrNumber' => 'TEST01',
            'segmentNumber' => '2',
        ]);

        $this->assertNotEmpty($details->cancellationDescriptions);
        $this->assertStringContainsString('CANCEL 24 HOURS', $details->cancellationDescriptions[0]);
        $this->assertEquals(1982.00, $details->totalAmountWithTax);
    }

    public function test_a_cancelled_segment_reports_as_deleted(): void
    {
        $this->transport = (new FakeTransport)->reply('PNR_AddMultiElements', 'pnr_cancel.xml');

        $confirm = $this->amadeusWith($this->transport)->addMultiElements('cancel', []);

        // pnr_cancel.xml keeps the RU segment and drops the HHL one
        $this->assertTrue($confirm->isSegmentDeleted('2'));
        $this->assertEquals('TEST01', $confirm->pnrNumber);
    }

    // -----------------------------------------------------------------
    // Session lifecycle across the chain
    // -----------------------------------------------------------------

    public function test_the_first_call_opens_a_session_and_stores_it(): void
    {
        $this->assertFalse($this->sessionManager->hasSession());

        $this->amadeus->hotelSearch('multi', $this->searchParams());

        $session = $this->sessionManager->getSessionData();
        $this->assertNotNull($session);
        $this->assertEquals('SESSIONTEST', $session->sessionId);
        $this->assertEquals(1, $session->sequenceNumber);
        $this->assertEquals('SECURITYTOKENTEST0000', $session->securityToken);
    }

    public function test_the_stored_sequence_advances_with_each_reply(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $this->assertEquals(1, $this->sessionManager->getSessionData()->sequenceNumber);

        $this->amadeus->addMultiElements('create', $this->passenger());
        $this->assertEquals(3, $this->sessionManager->getSessionData()->sequenceNumber);

        $this->amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);
        $this->assertEquals(6, $this->sessionManager->getSessionData()->sequenceNumber);
    }

    public function test_search_and_pnr_retrieve_do_not_send_a_session_body(): void
    {
        // Amadeus wants a Start session header for these two even mid-session,
        // which means credentials get re-sent. AmadeusSoap::hasSessionBody()
        // encodes that exception.
        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $this->amadeus->pnrRetrieve(['pnrNumber' => 'TEST01']);

        $this->assertFalse($this->transport->callTo('Hotel_MultiSingleAvailability')['hasSessionBody']);
        $this->assertFalse($this->transport->callTo('PNR_Retrieve')['hasSessionBody']);
    }

    public function test_other_operations_reuse_the_open_session(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $this->amadeus->addMultiElements('create', $this->passenger());

        $this->assertTrue($this->transport->callTo('PNR_AddMultiElements')['hasSessionBody']);
        $this->assertTrue($this->transport->callTo('PNR_AddMultiElements')['isStateful']);
    }

    public function test_sign_out_clears_the_stored_session(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $this->assertTrue($this->sessionManager->hasSession());

        $this->amadeus->signOut();

        $this->assertFalse($this->sessionManager->hasSession());
        $this->assertNull($this->sessionManager->getSessionData());
    }

    public function test_a_stateless_operation_never_opens_a_session(): void
    {
        $this->transport->reply('Hotel_DescriptiveInfo', <<<'XML'
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Body>
                    <OTA_HotelDescriptiveInfoRS xmlns="http://www.opentravel.org/OTA/2003/05">
                        <Success/>
                        <HotelDescriptiveContents>
                            <HotelDescriptiveContent HotelCode="CITST001"/>
                        </HotelDescriptiveContents>
                    </OTA_HotelDescriptiveInfoRS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            XML);

        $this->amadeus->hotelDescriptiveInfo(['hotelCode' => 'CITST001']);

        $call = $this->transport->callTo('Hotel_DescriptiveInfo');
        $this->assertFalse($call['isStateful']);
        $this->assertFalse($call['hasSessionBody']);
        $this->assertFalse($this->sessionManager->hasSession());
    }

    // -----------------------------------------------------------------
    // Request bodies
    // -----------------------------------------------------------------

    public function test_the_search_body_carries_the_requested_criteria(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());

        $body = $this->transport->callTo('Hotel_MultiSingleAvailability')['body'];

        $this->assertStringContainsString('MTY', $body);
        $this->assertStringContainsString('2027-05-19', $body);
        $this->assertStringContainsString('2027-05-20', $body);
    }

    public function test_the_sell_body_carries_the_hotel_and_passenger_reference(): void
    {
        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $create = $this->amadeus->addMultiElements('create', $this->passenger());

        $this->amadeus->hotelSell([
            'travelAgentRef' => $create->travelAgentRef,
            'chainCode' => 'CI',
            'cityCode' => 'MTY',
            'hotelCode' => 'CITST001',
            'bookingCode' => 'BCODE001',
            'paymentType' => 'CC',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'TRAVELER',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
        ]);

        $body = $this->transport->callTo('Hotel_Sell')['body'];

        $this->assertStringContainsString('<chainCode>CI</chainCode>', $body);
        $this->assertStringContainsString('<cityCode>MTY</cityCode>', $body);
        // HotelSell trims the property code to its last three characters
        $this->assertStringContainsString('<hotelCode>001</hotelCode>', $body);
        $this->assertStringContainsString('<value>BCODE001</value>', $body);
        $this->assertStringContainsString('<type>BHO</type>', $body);
    }

    public function test_the_create_body_carries_the_passenger_and_contact_email(): void
    {
        $this->amadeus->addMultiElements('create', $this->passenger());

        $body = $this->transport->callTo('PNR_AddMultiElements')['body'];

        $this->assertStringContainsString('<surname>TEST</surname>', $body);
        $this->assertStringContainsString('<firstName>TRAVELER</firstName>', $body);
        $this->assertStringContainsString('test@example.test', $body);
    }

    public function test_reservation_details_can_be_read_for_a_segment(): void
    {
        $this->transport = (new FakeTransport)
            ->reply('Hotel_CompleteReservationDetails', 'hotel_complete_reservation_details.xml');

        $amadeus = $this->amadeusWith($this->transport);

        $details = $amadeus->hotelCompleteReservationDetails([
            'pnrNumber' => 'TEST01',
            'segmentNumber' => '2',
        ]);

        $this->assertFalse($details->hasErrors);
        $this->assertEquals('MX', $details->countryCode);
        $this->assertEquals(1982.00, $details->totalAmountWithTax);
        $this->assertNotEmpty($details->cancellationDescriptions);
        $this->assertStringContainsString('CANCEL 24 HOURS', $details->cancellationDescriptions[0]);
        $this->assertNotEmpty($details->taxes);

        // The request identifies the PNR and the segment tattoo
        $body = $this->transport->callTo('Hotel_CompleteReservationDetails')['body'];
        $this->assertStringContainsString('<controlNumber>TEST01</controlNumber>', $body);
        $this->assertStringContainsString('<value>2</value>', $body);
    }

    // -----------------------------------------------------------------
    // Multi-room bookings
    // -----------------------------------------------------------------

    public function test_a_two_room_booking_builds_one_room_stay_per_room(): void
    {
        $this->transport = (new FakeTransport)
            ->reply('PNR_AddMultiElements', 'pnr_create.xml')
            ->reply('Hotel_Sell', 'hotel_sell_two_rooms.xml');

        $amadeus = $this->amadeusWith($this->transport);

        $amadeus->addMultiElements('create', [
            ['surname' => 'TEST', 'name' => 'ONE', 'type' => 'ADT', 'check_out_date' => '2027-05-20'],
            ['surname' => 'TEST', 'name' => 'TWO', 'type' => 'ADT', 'check_out_date' => '2027-05-20'],
        ]);

        $room = [
            'chainCode' => 'CI',
            'cityCode' => 'MTY',
            'hotelCode' => 'CITST001',
            'bookingCode' => 'BCODE001',
            'paymentType' => 'CC',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'ONE',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
        ];

        $sell = $amadeus->hotelSell([
            'travelAgentRef' => '1',
            'room1' => $room,
            'room2' => array_merge($room, [
                'bookingCode' => 'BCODE002',
                'firstName' => 'TWO',
                'passengerReference' => ['type' => 'BHO', 'value' => '3'],
            ]),
        ]);

        // Request carries both rooms
        $body = $this->transport->callTo('Hotel_Sell')['body'];
        $this->assertEquals(2, substr_count($body, '<roomStayData>'));
        $this->assertStringContainsString('<value>BCODE001</value>', $body);
        $this->assertStringContainsString('<value>BCODE002</value>', $body);

        // Reply yields one result per room, each with its own reservation
        $this->assertFalse($sell->hasErrors);
        $this->assertCount(2, $sell->roomResults);
        $this->assertEquals('3357244346', $sell->roomResults[0]->bookingReference);
        $this->assertEquals('3361946553', $sell->roomResults[1]->bookingReference);
        $this->assertEquals('BCODE001', $sell->roomResults[0]->bookingCode);
        $this->assertEquals('BCODE002', $sell->roomResults[1]->bookingCode);
    }

    public function test_a_multi_passenger_pnr_lists_every_traveller(): void
    {
        $this->transport = (new FakeTransport)->reply('PNR_AddMultiElements', 'pnr_create.xml');
        $amadeus = $this->amadeusWith($this->transport);

        $amadeus->addMultiElements('create', [
            ['surname' => 'TEST', 'name' => 'ONE', 'type' => 'ADT', 'check_out_date' => '2027-05-20'],
            ['surname' => 'TEST', 'name' => 'TWO', 'type' => 'ADT', 'check_out_date' => '2027-05-20'],
        ]);

        $body = $this->transport->callTo('PNR_AddMultiElements')['body'];

        $this->assertStringContainsString('<firstName>ONE</firstName>', $body);
        $this->assertStringContainsString('<firstName>TWO</firstName>', $body);
        $this->assertEquals(2, substr_count($body, '<travellerInfo>'));
    }

    // -----------------------------------------------------------------
    // Business errors
    // -----------------------------------------------------------------

    public function test_a_refused_sell_reports_its_error_code(): void
    {
        // Amadeus refuses a sell with a bare errorGroup: a code, no
        // errorWarningDescription, no roomStayData. Reporting nothing for that
        // shape made a failed booking look like a completed one.
        $this->transport = (new FakeTransport)->reply('Hotel_Sell', 'hotel_sell_rejected.xml');

        $sell = $this->amadeusWith($this->transport)->hotelSell([
            'travelAgentRef' => '1',
            'chainCode' => 'YZ',
            'cityCode' => 'MTY',
            'hotelCode' => 'YZMTY045',
            'bookingCode' => '1KN57JU',
            'paymentType' => '1',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'TESTER',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
        ]);

        $this->assertTrue($sell->hasErrors);
        $this->assertCount(1, $sell->errors);
        $this->assertEquals('CTL', $sell->errors[0]->code);
        $this->assertStringContainsString('CTL', $sell->errors[0]->message);
        $this->assertEmpty($sell->roomResults);
        $this->assertNull($sell->bookingReference);
    }

    public function test_the_sell_body_carries_the_city_from_the_property_code(): void
    {
        // An Amadeus property code is chain(2) + city(3) + property(3):
        // YZMTY045 is chain YZ, city MTY, property 045.
        $this->transport = (new FakeTransport)->reply('Hotel_Sell', 'hotel_sell.xml');

        $this->amadeusWith($this->transport)->hotelSell([
            'travelAgentRef' => '1',
            'chainCode' => 'YZ',
            'cityCode' => substr('YZMTY045', 2, 3),
            'hotelCode' => 'YZMTY045',
            'bookingCode' => '1KN57JU',
            'paymentType' => '1',
            'vendorCode' => 'AX',
            'cardNumber' => '370000000000002',
            'securityId' => '1234',
            'expiryDate' => '0628',
            'surname' => 'TEST',
            'firstName' => 'TESTER',
            'passengerReference' => ['type' => 'BHO', 'value' => '2'],
        ]);

        $body = $this->transport->callTo('Hotel_Sell')['body'];

        $this->assertStringContainsString('<chainCode>YZ</chainCode>', $body);
        $this->assertStringContainsString('<cityCode>MTY</cityCode>', $body);
        $this->assertStringContainsString('<hotelCode>045</hotelCode>', $body);
        $this->assertStringNotContainsString('<cityCode>YZM</cityCode>', $body);
    }

    public function test_a_business_error_surfaces_on_the_dto_without_throwing(): void
    {
        // Amadeus reports these inside a 200 response, so nothing throws;
        // hasErrors is the only signal the caller gets.
        $this->transport = (new FakeTransport)->reply('PNR_AddMultiElements', 'pnr_error.xml');
        $amadeus = $this->amadeusWith($this->transport);

        $create = $amadeus->addMultiElements('create', $this->passenger());

        $this->assertTrue($create->hasErrors);
        $this->assertCount(1, $create->errors);
        $this->assertEquals('INVALID FORMAT', $create->errors[0]->message);
        $this->assertEquals('1234', $create->errors[0]->code);
        $this->assertNull($create->pnrNumber);
    }

    public function test_a_failed_step_still_leaves_the_session_usable(): void
    {
        $this->transport = (new FakeTransport)
            ->reply('PNR_AddMultiElements', 'pnr_error.xml')
            ->reply('Security_SignOut', 'security_signout.xml');

        $amadeus = $this->amadeusWith($this->transport);

        $amadeus->addMultiElements('create', $this->passenger());

        // The error reply still carried a session, so cleanup can run
        $this->assertTrue($this->sessionManager->hasSession());

        $amadeus->signOut();

        $this->assertFalse($this->sessionManager->hasSession());
    }

    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    public function test_each_step_dispatches_start_and_completion_events(): void
    {
        Event::fake([OperationStarting::class, OperationCompleted::class]);

        $this->amadeus->hotelSearch('multi', $this->searchParams());
        $this->amadeus->signOut();

        Event::assertDispatched(OperationStarting::class, fn ($e) => $e->operation === 'Hotel_MultiSingleAvailability');
        Event::assertDispatched(OperationCompleted::class, fn ($e) => $e->operation === 'Hotel_MultiSingleAvailability' && $e->durationMs >= 0);
        Event::assertDispatched(OperationStarting::class, fn ($e) => $e->operation === 'Security_SignOut');
        Event::assertDispatchedTimes(OperationCompleted::class, 2);
    }
}
