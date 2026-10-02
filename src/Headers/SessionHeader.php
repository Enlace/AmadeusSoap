<?php

namespace Aldogtz\AmadeusSoap\Headers;

use Aldogtz\AmadeusSoap\Session\SessionData;
use SoapHeader;
use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;

class SessionHeader
{
    public static function start(): SoapHeader
    {
        $arrayToXml = new ArrayToXml([], [
            'rootElementName' => 'ses:Session',
            '_attributes' => [
                'xmlns:ses' => 'http://xml.amadeus.com/2010/06/Session_v3',
                'TransactionStatusCode' => 'Start',
            ],
        ]);

        $body = $arrayToXml->dropXmlDeclaration()->toXml();

        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Session_v3',
            'Session',
            new SoapVar($body, XSD_ANYXML)
        );
    }

    public static function inSeries(SessionData $session): SoapHeader
    {
        $incremented = $session->incrementSequence();

        $body = [
            'ses:SessionId' => $incremented->sessionId,
            'ses:SequenceNumber' => (string) $incremented->sequenceNumber,
            'ses:SecurityToken' => $incremented->securityToken,
        ];

        $arrayToXml = new ArrayToXml($body, [
            'rootElementName' => 'ses:Session',
            '_attributes' => [
                'xmlns:ses' => 'http://xml.amadeus.com/2010/06/Session_v3',
                'TransactionStatusCode' => 'InSeries',
            ],
        ]);

        $xml = $arrayToXml->dropXmlDeclaration()->toXml();

        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Session_v3',
            'Session',
            new SoapVar($xml, XSD_ANYXML)
        );
    }
}
