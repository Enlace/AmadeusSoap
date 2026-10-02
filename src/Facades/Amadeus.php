<?php

namespace Aldogtz\AmadeusSoap\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse hotelSearch(string $type = 'multi', array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelPricingResponse hotelPricing(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSellResponse hotelSell(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelDescriptiveInfoResponse hotelDescriptiveInfo(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelCompleteReservationDetailsResponse hotelCompleteReservationDetails(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse addMultiElements(string $type = 'create', array $params = [], array $remarks = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse pnrRetrieve(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\PnrCancelResponse pnrCancel(array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse signOut()
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse singOut()
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse recursiveHotelSearch(array $params = [])
 * @method static string|null getLastRequest()
 * @method static string|null getLastResponse()
 * @method static \Aldogtz\AmadeusSoap\Session\SessionManager session()
 *
 * @see \Aldogtz\AmadeusSoap\AmadeusSoap
 */
class Amadeus extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'amadeus-soap';
    }
}
