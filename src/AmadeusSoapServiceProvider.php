<?php

namespace Aldogtz\AmadeusSoap;

use Aldogtz\AmadeusSoap\Cache\OperationCache;
use Aldogtz\AmadeusSoap\Cache\SearchCacheLevel;
use Aldogtz\AmadeusSoap\Client\RetryHandler;
use Aldogtz\AmadeusSoap\Client\SoapClientFactory;
use Aldogtz\AmadeusSoap\Client\SoapTransport;
use Aldogtz\AmadeusSoap\Headers\HeaderBuilder;
use Aldogtz\AmadeusSoap\Logging\SoapLogger;
use Aldogtz\AmadeusSoap\Performance\PerformanceMonitor;
use Aldogtz\AmadeusSoap\RateFiltering\TwoPhaseSearchService;
use Aldogtz\AmadeusSoap\Security\AmaSecurityHeader;
use Aldogtz\AmadeusSoap\Security\WsSecurityHeader;
use Aldogtz\AmadeusSoap\Session\Contracts\SessionStore;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Session\Stores\ArraySessionStore;
use Aldogtz\AmadeusSoap\Session\Stores\CacheSessionStore;
use Aldogtz\AmadeusSoap\Session\Stores\FileSessionStore;
use Aldogtz\AmadeusSoap\Session\Stores\NullSessionStore;
use Aldogtz\AmadeusSoap\Session\Stores\RedisSessionStore;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use Illuminate\Support\Facades\Event;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class AmadeusSoapServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('amadeus-soap')
            ->hasConfigFile();
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(WsdlManager::class, function () {
            return new WsdlManager(config('amadeus-soap.wsdl_path'));
        });

        $this->app->singleton(SessionStore::class, function () {
            $config = config('amadeus-soap.session', []);
            $driver = $config['driver'] ?? 'redis';
            $prefix = $config['prefix'] ?? 'amadeus_session_';
            $ttl = $config['ttl'] ?? 900;

            return match ($driver) {
                'array' => new ArraySessionStore,
                'file' => new FileSessionStore(
                    path: $config['path'] ?? storage_path('framework/amadeus-sessions'),
                    prefix: $prefix,
                    ttl: $ttl,
                ),
                'cache' => new CacheSessionStore(
                    store: $config['store'] ?? 'file',
                    prefix: $prefix,
                    ttl: $ttl,
                ),
                'null' => new NullSessionStore,
                default => new RedisSessionStore(
                    connection: $config['connection'] ?? 'default',
                    prefix: $prefix,
                    ttl: $ttl,
                ),
            };
        });

        $this->app->singleton(SessionManager::class, function ($app) {
            $keyResolver = config('amadeus-soap.session.key_resolver')
                ?? fn () => auth()->id() ?? 'system';

            return new SessionManager(
                store: $app->make(SessionStore::class),
                keyResolver: $keyResolver,
                statelessOperations: config('amadeus-soap.stateless_operations', []),
            );
        });

        $this->app->singleton(SoapClientFactory::class, function () {
            return new SoapClientFactory(config('amadeus-soap.soap', []));
        });

        // Not a singleton: the scope is read from the current config every time,
        // so an instance never serves another office's or environment's entries.
        $this->app->bind(OperationCache::class, function ($app) {
            $config = config('amadeus-soap.cache', []);

            return new OperationCache(
                store: $app['cache']->store($config['store'] ?? null),
                ttls: $config['cacheable_operations'] ?? [],
                prefix: $config['prefix'] ?? 'amadeus_cache',
                // TST and production may share an office ID; AmadeusSoap also
                // keys entries by the WSDL's endpoint
                scope: implode('|', [
                    config('amadeus-soap.office_id'),
                    config('amadeus-soap.wsdl_path'),
                ]),
            );
        });

        $this->app->singleton(PerformanceMonitor::class, function ($app) {
            $config = config('amadeus-soap.monitoring', []);

            return new PerformanceMonitor(
                store: $app['cache']->store($config['store'] ?? null),
                storeHours: (int) ($config['store_hours'] ?? 24),
            );
        });

        $this->app->singleton(TwoPhaseSearchService::class, function ($app) {
            $levels = config('amadeus-soap.search_cache_level', []);

            return new TwoPhaseSearchService(
                amadeus: $app->make(AmadeusSoap::class),
                listingCacheLevel: $levels['listing'] ?? SearchCacheLevel::VERY_RECENT->value,
                detailsCacheLevel: $levels['details'] ?? SearchCacheLevel::VERY_RECENT->value,
            );
        });

        $this->app->singleton(AmadeusSoap::class, function ($app) {
            $config = config('amadeus-soap');

            $wsdlManager = $app->make(WsdlManager::class);
            $sessionManager = $app->make(SessionManager::class);

            $headerBuilder = new HeaderBuilder(
                security: new WsSecurityHeader(
                    $config['username'],
                    $config['password'],
                ),
                amaSecurity: new AmaSecurityHeader(
                    $config['office_id'],
                ),
                sessionManager: $sessionManager,
            );

            $retryConfig = $config['retry'] ?? [];
            $retryHandler = new RetryHandler(
                enabled: $retryConfig['enabled'] ?? false,
                maxAttempts: $retryConfig['max_attempts'] ?? 3,
                baseDelayMs: $retryConfig['base_delay_ms'] ?? 500,
                multiplier: (float) ($retryConfig['multiplier'] ?? 2.0),
                maxDelayMs: $retryConfig['max_delay_ms'] ?? 5000,
            );

            $transport = new SoapTransport(
                factory: $app->make(SoapClientFactory::class),
                headerBuilder: $headerBuilder,
                retryHandler: $retryHandler,
            );

            $loggingConfig = $config['logging'] ?? [];

            $logger = new SoapLogger(
                enabled: $loggingConfig['enabled'] ?? false,
                channel: $loggingConfig['channel'] ?? 'stack',
                operations: $loggingConfig['operations'] ?? [],
                level: $loggingConfig['level'] ?? 'debug',
            );

            return new AmadeusSoap(
                wsdlManager: $wsdlManager,
                sessionManager: $sessionManager,
                transport: $transport,
                logger: $logger,
                config: $config,
                cache: ($config['cache']['enabled'] ?? false) ? $app->make(OperationCache::class) : null,
            );
        });

        $this->app->alias(AmadeusSoap::class, 'amadeus-soap');
    }

    public function packageBooted(): void
    {
        if (config('amadeus-soap.monitoring.enabled', false)) {
            Event::subscribe(PerformanceMonitor::class);
        }
    }
}
