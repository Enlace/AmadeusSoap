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
            return new AmadeusSoap(config('amadeus-soap.wsdl'));
        });
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/amadeus-soap.php' => config_path('amadeus-soap.php'),
        ]);
    }
}