<?php

namespace Aldogtz\AmadeusSoap\Data\Responses;

use Aldogtz\AmadeusSoap\Data\Responses\Values\CancelPenalty;
use Aldogtz\AmadeusSoap\Data\Responses\Values\DailyRate;
use Aldogtz\AmadeusSoap\Data\Responses\Values\MealsIncluded;
use Aldogtz\AmadeusSoap\Data\Responses\Values\RoomTotal;
use Aldogtz\AmadeusSoap\Data\Responses\Values\Tax;

final readonly class RoomStayResult
{
    /**
     * @param  DailyRate[]  $dailyRates
     * @param  string[]  $amenities
     * @param  string  $hotelCode  Property the rate belongs to (from the HotelStay listing its RPH)
     * @param  int  $adults  Occupancy the rate was quoted for; 0 when the reply omits it
     * @param  array<int, array{age: string, count: string}>  $children
     * @param  string  $commissionStatusType  e.g. Commissionable, Non-paying; '' when the reply omits it
     * @param  CancelPenalty[]  $cancelPenalties
     * @param  Tax[]  $taxes  Taxes of the rate's total, as listed (not deduplicated)
     * @param  string[]  $acceptedCardCodes  Cards the guarantee accepts (VI, MC, AX…);
     *                                       empty when the reply lists none
     */
    public function __construct(
        public string $rph,
        public string $roomType,
        public string $roomTypeCode,
        public string $bookingCode,
        public string $ratePlanCode,
        public string $ratePlanCategory,
        public string $guaranteeCode,
        public string $numberOfUnits,
        /** null when the reply does not state it (CancelPenalty@NonRefundable missing) */
        public ?bool $nonRefundable,
        public ?RoomTotal $total,
        public string $currency,
        public string $start,
        public string $end,
        public array $dailyRates,
        public array $amenities,
        public MealsIncluded $meals,
        public string $hotelCode = '',
        public int $adults = 0,
        public array $children = [],
        public string $commissionStatusType = '',
        public string $commissionPercent = '',
        public array $cancelPenalties = [],
        public array $taxes = [],
        public array $acceptedCardCodes = [],
        public string $availabilityStatus = '',
    ) {}

    /**
     * Copy under a different RPH, used when merging paginated responses whose
     * RPH numbering restarts on each page.
     */
    public function withRph(string $rph): self
    {
        return new self(
            rph: $rph,
            roomType: $this->roomType,
            roomTypeCode: $this->roomTypeCode,
            bookingCode: $this->bookingCode,
            ratePlanCode: $this->ratePlanCode,
            ratePlanCategory: $this->ratePlanCategory,
            guaranteeCode: $this->guaranteeCode,
            numberOfUnits: $this->numberOfUnits,
            nonRefundable: $this->nonRefundable,
            total: $this->total,
            currency: $this->currency,
            start: $this->start,
            end: $this->end,
            dailyRates: $this->dailyRates,
            amenities: $this->amenities,
            meals: $this->meals,
            hotelCode: $this->hotelCode,
            adults: $this->adults,
            children: $this->children,
            commissionStatusType: $this->commissionStatusType,
            commissionPercent: $this->commissionPercent,
            cancelPenalties: $this->cancelPenalties,
            taxes: $this->taxes,
            acceptedCardCodes: $this->acceptedCardCodes,
            availabilityStatus: $this->availabilityStatus,
        );
    }
}
