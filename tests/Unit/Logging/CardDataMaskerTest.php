<?php

namespace Aldogtz\AmadeusSoap\Tests\Unit\Logging;

use Aldogtz\AmadeusSoap\Logging\CardDataMasker;
use PHPUnit\Framework\TestCase;

class CardDataMaskerTest extends TestCase
{
    public function test_the_card_number_keeps_its_last_four_digits(): void
    {
        $this->assertSame(
            '<ns1:ccInfo><ns1:cardNumber>XXXXXXXXXXXX1111</ns1:cardNumber></ns1:ccInfo>',
            CardDataMasker::mask('<ns1:ccInfo><ns1:cardNumber>4111111111111111</ns1:cardNumber></ns1:ccInfo>'),
        );
    }

    public function test_the_security_code_is_masked_entirely(): void
    {
        $this->assertSame('<securityId>XXXX</securityId>', CardDataMasker::mask('<securityId>1234</securityId>'));
    }

    public function test_reply_side_and_free_text_card_numbers_are_masked(): void
    {
        $xml = '<creditCardNumber>378282246310005</creditCardNumber><freetext>CCAX378282246310005EXP1230</freetext>';

        $this->assertSame(
            '<creditCardNumber>XXXXXXXXXXX0005</creditCardNumber><freetext>CC'.'AX'.'XXXXXXXXXXX0005EXP1230</freetext>',
            CardDataMasker::mask($xml),
        );
    }

    public function test_already_masked_values_and_other_elements_are_left_alone(): void
    {
        $xml = '<cardNumber>XXXXXXXXXXX0005</cardNumber><expiryDate>1230</expiryDate><bookingCode>1KN57JU</bookingCode>';

        $this->assertSame($xml, CardDataMasker::mask($xml));
    }
}
