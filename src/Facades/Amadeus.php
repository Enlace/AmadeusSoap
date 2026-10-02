<?php

namespace Aldogtz\AmadeusSoap\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse hotelSearch(string $type = 'multi', array $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelPricingResponse hotelPricing(array|\Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult $params = [], array $overrides = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSellResponse hotelSell(array|\Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult $params = [], ?\Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse $pnr = null, ?\Aldogtz\AmadeusSoap\Data\PaymentCard $card = null)
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelDescriptiveInfoResponse hotelDescriptiveInfo(array|string|\Aldogtz\AmadeusSoap\Data\Responses\HotelResult|\Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelCompleteReservationDetailsResponse hotelCompleteReservationDetails(array|\Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse|\Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse addMultiElements(string $type = 'create', array|\Aldogtz\AmadeusSoap\Data\Traveler $params = [], array $remarks = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse pnrRetrieve(array|string|\Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse|\Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\PnrCancelResponse pnrCancel(array|string|int|\Aldogtz\AmadeusSoap\Data\Responses\PnrSegment|\Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveSegment $params = [])
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse signOut()
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse singOut()
 * @method static \Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse recursiveHotelSearch(array $params = [], int $maxPages = 10)
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
