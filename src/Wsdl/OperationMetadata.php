<?php

namespace Aldogtz\AmadeusSoap\Wsdl;

final readonly class OperationMetadata
{
    public function __construct(
        public string $name,
        public string $wsdlId,
        public string $wsdlPath,
        public string $version,
        public string $inputMessageName,
        public string $outputMessageName,
        public string $soapAction,
        public string $serviceEndpoint,
        public string $rootElement,
        public string $responseRootElement,
        public string $responseNamespace,
    ) {}
}
