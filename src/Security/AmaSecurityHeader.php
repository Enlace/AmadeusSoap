<?php

namespace Aldogtz\AmadeusSoap\Security;

use SoapHeader;

class AmaSecurityHeader
{
    public function __construct(
        protected string $officeId,
    ) {}

    public function generate(): SoapHeader
    {
        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Security_v1',
            'AMA_SecurityHostedUser',
            ['UserID' => [
                '_' => '',
                'POS_Type' => '1',
                'PseudoCityCode' => $this->officeId,
                'AgentDutyCode' => 'SU',
                'RequestorType' => 'U',
            ]]
        );
    }
}
