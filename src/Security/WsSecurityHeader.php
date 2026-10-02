<?php

namespace Aldogtz\AmadeusSoap\Security;

use Illuminate\Support\Carbon;
use SoapHeader;
use SoapVar;

class WsSecurityHeader
{
    public function __construct(
        protected string $username,
        protected string $password,
    ) {}

    public function generate(): SoapHeader
    {
        $nonce = random_bytes(32);
        $encodedNonce = base64_encode($nonce);
        date_default_timezone_set('UTC');
        $timestamp = Carbon::now()->toIso8601String();
        $passSHA = base64_encode(sha1($nonce.$timestamp.sha1($this->password, true), true));

        $xml = '<oas:Security xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <oas:UsernameToken xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" oas1:Id="UsernameToken-1">
            <oas:Username>'.$this->username.'</oas:Username>
            <oas:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'.$encodedNonce.'</oas:Nonce>
            <oas:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'.$passSHA.'</oas:Password>
            <oas1:Created>'.$timestamp.'</oas1:Created>
            </oas:UsernameToken>
            </oas:Security>';

        return new SoapHeader(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wsswssecurity-secext-1.0.xsd',
            'Security',
            new SoapVar($xml, XSD_ANYXML)
        );
    }
}
