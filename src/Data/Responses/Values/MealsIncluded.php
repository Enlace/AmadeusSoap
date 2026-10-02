<?php

namespace Aldogtz\AmadeusSoap\Data\Responses\Values;

final readonly class MealsIncluded
{
    public function __construct(
        public string $mealPlanCodes,
        public string $breakfast,
        public string $mealPlanIndicator,
    ) {}
}
