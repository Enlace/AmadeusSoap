<?php

namespace Aldogtz\AmadeusSoap;

use Illuminate\Support\ServiceProvider;
use Aldogtz\AmadeusSoap\Services\AmadeusSoap;

class AmadeusSoapServiceProvider extends ServiceProvider{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('AmadeusSoap', function() {
            return new AmadeusSoap(config('AmadeusSoap.wsdl'));
        });
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }
}