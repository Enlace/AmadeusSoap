<?php

namespace Aldogtz\AmadeusSoap\Headers;

use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;

class BodyBuilder
{
    public static function build(array $params, string $rootElement, array $attributes = []): SoapVar
    {
        $arrayToXml = new ArrayToXml($params, [
            'rootElementName' => $rootElement,
            '_attributes' => $attributes,
        ]);

        $body = $arrayToXml->dropXmlDeclaration()->prettify()->toXml();

        return new SoapVar($body, XSD_ANYXML);
    }
}
