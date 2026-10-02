<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\Responses\Values\DailyRate;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RoomTotal;

final readonly class HotelResult
{
    /**
     * @param  DailyRate[]  $dailyRates
     * @param  string[]  $roomStayRPHs  Every RPH this property offers
     */
    public function __construct(
        public string $hotelCode,
        public string $hotelName,
        public string $chainCode,
        public string $ratingCode,
        public string $countryCode,
        public string $roomStayRPH,
        public ?RoomTotal $total,
        public array $dailyRates,
        public string $ratePlanCode,
        public string $ratePlanCategory,
        public string $start,
        public string $end,
        public array $roomStayRPHs = [],
    ) {}

    /**
     * Copy with a different set of RPHs, used when merging paginated
     * responses whose RPH numbering restarts on each page.
     *
     * @param  string[]  $roomStayRPHs
     */
    public function withRoomStayRPHs(array $roomStayRPHs): self
    {
        return new self(
            hotelCode: $this->hotelCode,
            hotelName: $this->hotelName,
            chainCode: $this->chainCode,
            ratingCode: $this->ratingCode,
            countryCode: $this->countryCode,
            roomStayRPH: implode(' ', $roomStayRPHs),
            total: $this->total,
            dailyRates: $this->dailyRates,
            ratePlanCode: $this->ratePlanCode,
            ratePlanCategory: $this->ratePlanCategory,
            start: $this->start,
            end: $this->end,
            roomStayRPHs: $roomStayRPHs,
        );
    }

    /**
     * Pick this property's RoomStayResult objects out of a search response.
     *
     * Amadeus returns hotels and room stays as two parallel collections; a
     * property points at its rates through RoomStayRPH, which is a
     * space-separated list when the property has more than one rate.
     *
     * @param  RoomStayResult[]  $roomStays  Usually $response->roomStays
     * @return RoomStayResult[]
     */
    public function roomStays(array $roomStays): array
    {
        $wanted = array_flip($this->roomStayRPHs);

        return array_values(array_filter(
            $roomStays,
            fn (RoomStayResult $roomStay) => isset($wanted[$roomStay->rph]),
        ));
    }
}
