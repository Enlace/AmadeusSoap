<?php

return [

    /*
    |--------------------------------------------------------------------------
    | WSDL Directory Path
    |--------------------------------------------------------------------------
    |
    | Path to the directory containing Amadeus WSDL files.
    |
    */
    'wsdl_path' => env('AMADEUS_WSDL_PATH'),

    /*
    |--------------------------------------------------------------------------
    | Credentials
    |--------------------------------------------------------------------------
    */
    'username' => env('AMADEUS_USERNAME'),
    'password' => env('AMADEUS_PASSWORD'),
    'office_id' => env('AMADEUS_OFFICE_ID'),

    /*
    |--------------------------------------------------------------------------
    | Endpoint Override
    |--------------------------------------------------------------------------
    |
    | If set, overrides the endpoint defined in the WSDL files.
    |
    */
    'endpoint' => env('AMADEUS_ENDPOINT'),

    /*
    |--------------------------------------------------------------------------
    | Session Configuration
    |--------------------------------------------------------------------------
    |
    | Supported drivers: "redis", "cache", "file", "array", "null"
    |
    | redis  — Direct Redis via Laravel Redis facade (requires ext-redis or predis)
    | cache  — Laravel Cache facade (supports file, database, redis, memcached, etc.)
    | file   — JSON files on disk (good for development without Redis)
    | array  — In-memory only (ideal for testing, lost on process exit)
    | null   — No-op store (fully stateless, no session persistence)
    |
    */
    'session' => [
        'driver' => env('AMADEUS_SESSION_DRIVER', 'redis'),

        // Redis driver settings
        'connection' => env('AMADEUS_SESSION_CONNECTION', 'default'),

        // Cache driver settings (Laravel cache store name)
        'store' => env('AMADEUS_SESSION_CACHE_STORE', 'file'),

        // File driver settings
        'path' => storage_path('framework/amadeus-sessions'),

        // Shared settings
        'prefix' => env('AMADEUS_SESSION_PREFIX', 'amadeus_session_'),
        'ttl' => (int) env('AMADEUS_SESSION_TTL', 900),

        // Callable to resolve the session key per user.
        // Default: Auth::id() ?? 'system'
        'key_resolver' => null,

        // Single-hotel searches and PNR_Retrieve always start a new session.
        // Sign the stored one out first instead of leaving it open on Amadeus
        // until it times out (open sessions count against the office's limit).
        'sign_out_replaced' => (bool) env('AMADEUS_SESSION_SIGN_OUT_REPLACED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | SOAP Client Options
    |--------------------------------------------------------------------------
    */
    'soap' => [
        'trace' => (bool) env('AMADEUS_SOAP_TRACE', true),
        'exceptions' => true,
        'cache_wsdl' => WSDL_CACHE_MEMORY,
        'connection_timeout' => (int) env('AMADEUS_CONNECTION_TIMEOUT', 30),
        'timeout' => (int) env('AMADEUS_TIMEOUT', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */
    'logging' => [
        'enabled' => (bool) env('AMADEUS_LOGGING', false),
        'channel' => env('AMADEUS_LOG_CHANNEL', 'stack'),
        'operations' => [],
        'level' => 'debug',
    ],

    /*
    |--------------------------------------------------------------------------
    | Retry Configuration
    |--------------------------------------------------------------------------
    |
    | Automatic retry with exponential backoff for transient errors
    | (connection timeouts, SSL failures, temporary Amadeus outages).
    |
    | Only ConnectionException errors are retried — SoapFaultExceptions
    | (business logic errors) are NOT retried.
    |
    */
    'retry' => [
        'enabled' => (bool) env('AMADEUS_RETRY_ENABLED', false),
        'max_attempts' => (int) env('AMADEUS_RETRY_MAX_ATTEMPTS', 3),
        'base_delay_ms' => (int) env('AMADEUS_RETRY_BASE_DELAY_MS', 500),
        'multiplier' => (float) env('AMADEUS_RETRY_MULTIPLIER', 2.0),
        'max_delay_ms' => (int) env('AMADEUS_RETRY_MAX_DELAY_MS', 5000),
    ],

    /*
    |--------------------------------------------------------------------------
    | Debug Mode
    |--------------------------------------------------------------------------
    */
    'debug' => (bool) env('AMADEUS_DEBUG', false),

    /*
    |--------------------------------------------------------------------------
    | Stateless Operations
    |--------------------------------------------------------------------------
    |
    | Operations that never participate in a session.
    |
    */
    'stateless_operations' => [
        'Hotel_DescriptiveInfo',
    ],

    /*
    |--------------------------------------------------------------------------
    | Retention Line Defaults
    |--------------------------------------------------------------------------
    */
    'retention' => [
        'months' => 6,
        'city_code' => 'MTY',
        'max_days' => 361,
        'free_text' => 'HOTEL BOOKING RETENTION',
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Contact Email
    |--------------------------------------------------------------------------
    */
    'contact_email' => env('AMADEUS_CONTACT_EMAIL', 'desarollo@enlaceforte.com'),


    /*
    |--------------------------------------------------------------------------
    | Response Cache
    |--------------------------------------------------------------------------
    |
    | Caches the raw response XML of stateless calls: multi-hotel searches by
    | city or coordinates, and descriptive info. Stateful calls (single-hotel
    | search, pricing, sell, PNR) are never cached, even if listed here: their
    | response carries the session the booking flow continues.
    |
    | Responses with errors are not cached. Entries are scoped per office ID.
    | Call OperationCache::flush() to invalidate everything.
    |
    */
    'cache' => [
        'enabled' => (bool) env('AMADEUS_CACHE_ENABLED', false),

        // Laravel cache store name (null = default store)
        'store' => env('AMADEUS_CACHE_STORE'),

        'prefix' => env('AMADEUS_CACHE_PREFIX', 'amadeus_cache'),

        // TTL in seconds per operation
        'cacheable_operations' => [
            'Hotel_MultiSingleAvailability' => (int) env('AMADEUS_CACHE_SEARCH_TTL', 300),
            'Hotel_DescriptiveInfo' => (int) env('AMADEUS_CACHE_INFO_TTL', 3600),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Monitoring
    |--------------------------------------------------------------------------
    |
    | Records response time and success of every SOAP call (from the
    | OperationCompleted / OperationFailed events) in the cache store.
    | Read them with PerformanceMonitor::getMetrics($operation, $hours).
    |
    */
    'monitoring' => [
        'enabled' => (bool) env('AMADEUS_MONITORING_ENABLED', false),

        // Laravel cache store name (null = default store)
        'store' => env('AMADEUS_MONITORING_STORE'),

        'store_hours' => (int) env('AMADEUS_MONITORING_STORE_HOURS', 24),
    ],

    /*
    |--------------------------------------------------------------------------
    | Amadeus SearchCacheLevel
    |--------------------------------------------------------------------------
    |
    | Amadeus' own server-side availability cache. Valid values (from the
    | Amadeus schema): Live, VeryRecent, LessRecent.
    |
    | default — used by hotelSearch() when the call does not set
    |           search_cache_level. Keep Live unless you know you can
    |           afford slightly older availability.
    | listing / details — used by TwoPhaseSearchService.
    |
    */
    'search_cache_level' => [
        'default' => env('AMADEUS_DEFAULT_SEARCH_CACHE_LEVEL', 'Live'),
        'listing' => env('AMADEUS_LISTING_CACHE_LEVEL', 'VeryRecent'),
        'details' => env('AMADEUS_DETAILS_CACHE_LEVEL', 'VeryRecent'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Filtering
    |--------------------------------------------------------------------------
    |
    | default_strategy — BestOnlyIndicator for multi-hotel searches that do not
    | set rate_strategy: "best_only" (one rate per hotel) or "all_rates".
    |
    */
    'rate_filtering' => [
        'default_strategy' => env('AMADEUS_DEFAULT_RATE_STRATEGY', 'best_only'),
    ],

];
