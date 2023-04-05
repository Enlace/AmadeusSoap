<?php

namespace Aldogtz\AmadeusSoap\Facades;

use Illuminate\Support\Facades\Facade;

class AmadeusSoapFacade extends Facade
{
    /**
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'AmadeusSoap';
    }
}