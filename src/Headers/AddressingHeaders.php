<?php

namespace Aldogtz\AmadeusSoap\Headers;

use Illuminate\Support\Str;
use SoapHeader;

class AddressingHeaders
{
    public static function messageId(): SoapHeader
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'MessageID',
            (string) Str::uuid()
        );
    }

    public static function action(string $soapAction): SoapHeader
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'Action',
            $soapAction
        );
    }

    public static function to(string $endpoint): SoapHeader
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'To',
            $endpoint
        );
    }
}
