<?php

namespace Aldogtz\AmadeusSoap\Operations\Concerns;

trait BuildsGuestCounts
{
    protected function buildGuestCounts(string $guestCount, array $children = []): array
    {
        $adults = [
            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $guestCount],
        ];

        if (empty($children)) {
            return $adults;
        }

        $counts = [];

        foreach ($children as $child) {
            $counts[] = [
                '_attributes' => [
                    'AgeQualifyingCode' => '8',
                    'Count' => $child['count'],
                    'Age' => $child['age'],
                ],
            ];
        }

        $counts[] = $adults;

        return $counts;
    }
}
