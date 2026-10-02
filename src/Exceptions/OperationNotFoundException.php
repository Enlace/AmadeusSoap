<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

class OperationNotFoundException extends AmadeusSoapException
{
    public static function forOperation(string $operation): self
    {
        return new self("Operation '{$operation}' is not defined in the WSDL files.");
    }
}
