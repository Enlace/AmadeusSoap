<?php

namespace Aldogtz\AmadeusSoap\Headers;

use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Wsdl\OperationMetadata;
use SoapHeader;

class HeaderBuilder
{
    public function __construct(
        protected WsSecurityHeader $security,
        protected AmaSecurityHeader $amaSecurity,
        protected SessionManager $sessionManager,
    ) {}

    /**
     * Build all required SOAP headers for a given operation.
     *
     * @return SoapHeader[]
     */
    public function build(OperationMetadata $metadata, bool $isStateful, bool $hasSessionBody): array
    {
        $headers = [];

        if ($isStateful) {
            $sessionData = $this->sessionManager->getSessionData();

            if ($sessionData !== null && $hasSessionBody) {
                $headers[] = SessionHeader::inSeries($sessionData);
            } else {
                $headers[] = SessionHeader::start();
            }
        }

        $headers[] = AddressingHeaders::messageId();
        $headers[] = AddressingHeaders::action($metadata->soapAction);
        $headers[] = AddressingHeaders::to($metadata->serviceEndpoint);

        // WS-Security and AMA headers are only added for:
        // - Stateless operations (always)
        // - Stateful operations that don't have session body (new session start)
        if (! $isStateful || ! $hasSessionBody) {
            $headers[] = $this->security->generate();
            $headers[] = $this->amaSecurity->generate();
        }

        return $headers;
    }
}
