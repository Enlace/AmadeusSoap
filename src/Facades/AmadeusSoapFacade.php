<?php

namespace Aldogtz\AmadeusSoap\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \DOMXPath Hotel_MultiSingleAvailability(array $params = []) Performs hotel availability search for single or multiple properties
 * @method static \DOMXPath Hotel_EnhancedPricing(array $params = []) Retrieves detailed pricing information for a specific hotel room rate
 * @method static \DOMXPath Hotel_Sell(array $params = []) Creates a hotel reservation segment in the PNR
 * @method static \DOMXPath Hotel_DescriptiveInfo(array $params = []) Retrieves descriptive information about hotel properties
 * @method static \DOMXPath Hotel_CompleteReservationDetails(array $params = []) Retrieves complete details of a hotel reservation
 * @method static \DOMXPath PNR_AddMultiElements(array $params = []) Adds multiple elements (passengers, data) to a PNR
 * @method static \DOMXPath PNR_Retrieve(array $params = []) Retrieves a PNR by its record locator
 * @method static \DOMXPath PNR_Cancel(array $params = []) Cancels elements or segments from a PNR
 * @method static \DOMXPath Security_SignOut() Ends the current Amadeus session and clears session data
 * @method static \DOMXPath HotelSearch(string $type = 'multi', array $params = []) Performs a hotel search with the specified type and parameters
 * @method static \DOMXPath hotelPricing(array $params = []) Gets detailed pricing for a specific hotel room
 * @method static \DOMXPath hotelSell(array $params = []) Creates a hotel reservation in the PNR
 * @method static \DOMXPath hotelDescriptiveInfo(array $params = []) Gets comprehensive hotel information including amenities and policies
 * @method static \DOMXPath pnrRetrieve(array $params = []) Retrieves a PNR using the PNR number
 * @method static \DOMXPath hotelCompleteReservationDetails(array $params = []) Gets complete hotel reservation details
 * @method static \DOMXPath pnrCancel(array $params = []) Cancels segments from a PNR
 * @method static \DOMXPath singOut() Signs out from the current Amadeus session
 * @method static \DOMXPath recursiveHotelSearch(string $type = 'multi', array $params = []) Performs recursive hotel search with pagination support
 * @method static \DOMXPath addMultiElements(string $type = 'create', array $params = []) Adds multiple elements to a PNR (create, end, or cancel)
 * @method static bool|string getLastRequest() Gets the last SOAP request XML
 * @method static bool|string getLastResponse() Gets the last SOAP response XML
 *
 * @see \Aldogtz\AmadeusSoap\Services\AmadeusSoap
 *
 * @package Aldogtz\AmadeusSoap\Facades
 */
class AmadeusSoapFacade extends Facade
{
    /**
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'AmadeusSoap';
    }
}