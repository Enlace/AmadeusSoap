<?php

namespace Aldogtz\AmadeusSoap\Operations;

use Aldogtz\AmadeusSoap\Operations\Contracts\Operation;

class SecuritySignOut implements Operation
{
    public function getOperationName(): string
    {
        return 'Security_SignOut';
    }

    public function build(): array
    {
        return [];
    }
}
