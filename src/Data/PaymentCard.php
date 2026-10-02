<?php

namespace Aldogtz\AmadeusSoap\Data;

/**
 * Card that guarantees a hotel sell.
 *
 * The number and security code are marked sensitive (redacted from stack
 * traces) and masked in var_dump()/dd(), so the card does not leak into logs.
 */
final readonly class PaymentCard
{
    /**
     * @param  string  $vendorCode  Amadeus card vendor code, e.g. VI, CA, AX
     * @param  string  $expiry  MMYY
     */
    public function __construct(
        public string $vendorCode,
        #[\SensitiveParameter] public string $number,
        #[\SensitiveParameter] public string $securityCode,
        public string $expiry,
        public string $holderName,
    ) {}

    public function maskedNumber(): string
    {
        return str_repeat('X', max(0, strlen($this->number) - 4)).substr($this->number, -4);
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'vendorCode' => $this->vendorCode,
            'number' => $this->maskedNumber(),
            'securityCode' => '***',
            'expiry' => $this->expiry,
            'holderName' => $this->holderName,
        ];
    }
}
