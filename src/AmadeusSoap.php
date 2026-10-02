<?php

namespace Aldogtz\AmadeusSoap;

use Aldogtz\AmadeusSoap\Cache\OperationCache;
use Aldogtz\AmadeusSoap\Client\SoapTransport;
use Aldogtz\AmadeusSoap\Data\AmadeusResponse;
use Aldogtz\AmadeusSoap\Data\HotelCompleteReservationDetailsParams;
use Aldogtz\AmadeusSoap\Data\HotelDescriptiveInfoParams;
use Aldogtz\AmadeusSoap\Data\HotelPricingParams;
use Aldogtz\AmadeusSoap\Data\HotelSearchParams;
use Aldogtz\AmadeusSoap\Data\HotelSellParams;
use Aldogtz\AmadeusSoap\Data\PaymentCard;
use Aldogtz\AmadeusSoap\Data\PnrCancelParams;
use Aldogtz\AmadeusSoap\Data\PnrRetrieveParams;
use Aldogtz\AmadeusSoap\Data\Responses\HotelResult;
use Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveSegment;
use Aldogtz\AmadeusSoap\Data\Responses\PnrSegment;
use Aldogtz\AmadeusSoap\Data\Responses\RoomStayResult;
use Aldogtz\AmadeusSoap\Data\Traveler;
use Aldogtz\AmadeusSoap\Data\Responses\AddMultiElementsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelCompleteReservationDetailsResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelDescriptiveInfoResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelPricingResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSearchResponse;
use Aldogtz\AmadeusSoap\Data\Responses\HotelSellResponse;
use Aldogtz\AmadeusSoap\Data\Responses\PnrCancelResponse;
use Aldogtz\AmadeusSoap\Data\Responses\PnrRetrieveResponse;
use Aldogtz\AmadeusSoap\Data\Responses\SignOutResponse;
use Aldogtz\AmadeusSoap\Events\OperationCompleted;
use Aldogtz\AmadeusSoap\Events\OperationFailed;
use Aldogtz\AmadeusSoap\Events\OperationStarting;
use Aldogtz\AmadeusSoap\Exceptions\AuthenticationException;
use Aldogtz\AmadeusSoap\Exceptions\ConnectionException;
use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;
use Aldogtz\AmadeusSoap\Exceptions\OperationNotFoundException;
use Aldogtz\AmadeusSoap\Exceptions\SessionException;
use Aldogtz\AmadeusSoap\Exceptions\SoapFaultException;
use Aldogtz\AmadeusSoap\Exceptions\XmlParseException;
use Aldogtz\AmadeusSoap\Headers\BodyBuilder;
use Aldogtz\AmadeusSoap\Logging\SoapLogger;
use Aldogtz\AmadeusSoap\Operations\HotelCompleteReservationDetails;
use Aldogtz\AmadeusSoap\Operations\HotelDescriptiveInfo;
use Aldogtz\AmadeusSoap\Operations\HotelPricing;
use Aldogtz\AmadeusSoap\Operations\HotelSearch;
use Aldogtz\AmadeusSoap\Operations\HotelSell;
use Aldogtz\AmadeusSoap\Operations\PnrAddMultiElements;
use Aldogtz\AmadeusSoap\Operations\PnrCancel;
use Aldogtz\AmadeusSoap\Operations\PnrRetrieve;
use Aldogtz\AmadeusSoap\Operations\SecuritySignOut;
use Aldogtz\AmadeusSoap\Session\SessionManager;
use Aldogtz\AmadeusSoap\Wsdl\WsdlManager;
use SoapVar;

class AmadeusSoap
{
    public function __construct(
        protected WsdlManager $wsdlManager,
        protected SessionManager $sessionManager,
        protected SoapTransport $transport,
        protected SoapLogger $logger,
        protected array $config,
        protected ?OperationCache $cache = null,
    ) {}

    /**
     * Search for hotel availability.
     *
     * When rate_filter_criteria is given, the returned room stays are
     * filtered locally (see RateFilterCriteria).
     *
     * @throws SoapFaultException
     * @throws OperationNotFoundException
     */
    public function hotelSearch(string $type = 'multi', array $params = []): HotelSearchResponse
    {
        $searchParams = HotelSearchParams::fromArray(array_merge($this->searchDefaults(), $params, ['type' => $type]));
        $operation = new HotelSearch($searchParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $metadata = $this->wsdlManager->getRegistry()->get($operationName);
        $soapBody = BodyBuilder::build($body, $metadata->rootElement);

        $isStateful = $operation->isStateful($soapBody);
        $hasSessionBody = $this->hasSessionBody($operationName) && $this->sessionManager->hasSession();

        $response = HotelSearchResponse::fromResponse(
            $this->executeOperation($operationName, $soapBody, $isStateful, $hasSessionBody)
        );

        return $searchParams->rateFilterCriteria !== null
            ? $response->filterRoomStays($searchParams->rateFilterCriteria)
            : $response;
    }

    /**
     * Get enhanced pricing for a hotel.
     *
     * Pass the room stay from a single-hotel search to take hotel, dates,
     * codes and occupancy from it ($overrides wins), or the params array.
     */
    public function hotelPricing(array|RoomStayResult $params = [], array $overrides = []): HotelPricingResponse
    {
        $pricingParams = $params instanceof RoomStayResult
            ? HotelPricingParams::fromRoomStay($params, $overrides)
            : HotelPricingParams::fromArray(array_merge($params, $overrides));
        $operation = new HotelPricing($pricingParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $response = $this->executeStandardOperation($operationName, $body);

        return HotelPricingResponse::fromResponse($response);
    }

    /**
     * Sell a hotel room (create a booking segment).
     *
     * Pass the room stay, the PNR reply and the card to derive every sell
     * param (see HotelSellParams::forRoom()), or the params array.
     *
     * @throws InvalidParameterException
     */
    public function hotelSell(array|RoomStayResult $params = [], ?AddMultiElementsResponse $pnr = null, ?PaymentCard $card = null): HotelSellResponse
    {
        if ($params instanceof RoomStayResult) {
            if ($pnr === null || $card === null) {
                throw InvalidParameterException::forValidation('HotelSellParams', [
                    'pnr' => 'selling a room stay needs the PNR reply and the guarantee card',
                ]);
            }

            $params = HotelSellParams::forRoom($params, $pnr, $card);
        }

        $operation = new HotelSell(HotelSellParams::normalize($params));
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $response = $this->executeStandardOperation($operationName, $body);

        return HotelSellResponse::fromResponse($response);
    }

    /**
     * Get hotel descriptive information.
     *
     * @throws SoapFaultException
     * @throws OperationNotFoundException
     */
    public function hotelDescriptiveInfo(array|string|HotelResult|RoomStayResult $params = []): HotelDescriptiveInfoResponse
    {
        $infoParams = HotelDescriptiveInfoParams::fromArray(match (true) {
            is_string($params) => ['hotelCode' => $params],
            $params instanceof HotelResult, $params instanceof RoomStayResult => ['hotelCode' => $params->hotelCode],
            default => $params,
        });
        $operation = new HotelDescriptiveInfo($infoParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $metadata = $this->wsdlManager->getRegistry()->get($operationName);
        $soapBody = BodyBuilder::build($body, $metadata->rootElement);

        // Hotel_DescriptiveInfo is always stateless
        $response = $this->executeOperation($operationName, $soapBody, false, false);

        return HotelDescriptiveInfoResponse::fromResponse($response);
    }

    /**
     * Get complete hotel reservation details.
     *
     * Pass the end-transaction or retrieve reply to use its PNR and first
     * hotel segment, or the params array.
     */
    public function hotelCompleteReservationDetails(array|AddMultiElementsResponse|PnrRetrieveResponse $params = []): HotelCompleteReservationDetailsResponse
    {
        if (! is_array($params)) {
            $params = ['pnrNumber' => $params->pnrNumber, 'segmentNumber' => $params->segments[0]->segmentNumber ?? null];
        }

        $detailParams = HotelCompleteReservationDetailsParams::fromArray(array_filter($params, fn ($value) => $value !== null));
        $operation = new HotelCompleteReservationDetails($detailParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $response = $this->executeStandardOperation($operationName, $body);

        return HotelCompleteReservationDetailsResponse::fromResponse($response);
    }

    /**
     * Add multi elements to PNR (create, end, cancel).
     *
     * For 'create', pass a Traveler (or a list of them) or the params array.
     *
     * @param  array<int|string, mixed>|Traveler|Traveler[]  $params
     */
    public function addMultiElements(string $type = 'create', array|Traveler $params = [], array $remarks = []): AddMultiElementsResponse
    {
        $params = match (true) {
            $params instanceof Traveler => $params->toArray(),
            default => array_map(fn ($traveler) => $traveler instanceof Traveler ? $traveler->toArray() : $traveler, $params),
        };

        // first_name is accepted as the snake_case spelling of name
        if (isset($params['first_name'])) {
            $params['name'] ??= $params['first_name'];
        }

        $operation = new PnrAddMultiElements(
            type: $type,
            params: $params,
            remarks: $remarks,
            retentionConfig: $this->config['retention'] ?? [],
            contactEmail: $this->config['contact_email'] ?? 'desarollo@enlaceforte.com',
        );
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $response = $this->executeStandardOperation($operationName, $body);

        return AddMultiElementsResponse::fromResponse($response);
    }

    /**
     * Retrieve a PNR.
     *
     * @throws SoapFaultException
     * @throws OperationNotFoundException
     */
    public function pnrRetrieve(array|string|AddMultiElementsResponse|PnrRetrieveResponse $params = []): PnrRetrieveResponse
    {
        $retrieveParams = PnrRetrieveParams::fromArray(match (true) {
            is_string($params) => ['pnrNumber' => $params],
            is_array($params) => $params,
            default => ['pnrNumber' => $params->pnrNumber],
        });
        $operation = new PnrRetrieve($retrieveParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $metadata = $this->wsdlManager->getRegistry()->get($operationName);
        $soapBody = BodyBuilder::build($body, $metadata->rootElement);

        // PNR_Retrieve: stateful but does not use session body
        $hasSessionBody = false;

        $response = $this->executeOperation($operationName, $soapBody, true, $hasSessionBody);

        return PnrRetrieveResponse::fromResponse($response);
    }

    /**
     * Cancel PNR segments.
     *
     * Pass the segment (from the end-transaction or retrieve reply), its
     * number, or the params array.
     */
    public function pnrCancel(array|string|int|PnrSegment|PnrRetrieveSegment $params = []): PnrCancelResponse
    {
        $cancelParams = PnrCancelParams::fromArray(match (true) {
            is_array($params) => $params,
            is_object($params) => ['segmentNumber' => $params->segmentNumber],
            default => ['segmentNumber' => (string) $params],
        });
        $operation = new PnrCancel($cancelParams);
        $body = $operation->build();
        $operationName = $operation->getOperationName();

        $response = $this->executeStandardOperation($operationName, $body);

        return PnrCancelResponse::fromResponse($response);
    }

    /**
     * Sign out from the Amadeus session.
     *
     * @throws SoapFaultException
     * @throws OperationNotFoundException
     */
    public function signOut(): SignOutResponse
    {
        $operation = new SecuritySignOut;
        $operationName = $operation->getOperationName();

        $metadata = $this->wsdlManager->getRegistry()->get($operationName);
        $soapBody = BodyBuilder::build($operation->build(), $metadata->rootElement);

        $response = $this->executeOperation($operationName, $soapBody, true, true);

        $this->sessionManager->clearSession();

        return SignOutResponse::fromResponse($response);
    }

    /**
     * @deprecated Use signOut() instead.
     */
    public function singOut(): SignOutResponse
    {
        return $this->signOut();
    }

    /**
     * Recursive hotel search with pagination support.
     *
     * @throws SoapFaultException
     * @throws OperationNotFoundException
     */
    public function recursiveHotelSearch(array $params = [], int $maxPages = 10): HotelSearchResponse
    {
        $response = $this->hotelSearch('multi', $params);

        $seenTokens = [];
        $pages = 1;

        while (
            $pages < $maxPages
            && ! empty($response->moreIndicator)
            && ! isset($seenTokens[$response->moreIndicator])
        ) {
            // Guard against a server that keeps handing back the same token
            $seenTokens[$response->moreIndicator] = true;

            $next = $this->hotelSearch('multi', array_merge($params, [
                'more_data_echo_token' => $response->moreIndicator,
            ]));

            // A page that returned nothing usable ends the walk; keep what we
            // already have rather than discarding it.
            if (! $next->ok && $next->hotels === []) {
                break;
            }

            $response = $response->mergePage($next);
            $pages++;
        }

        return $response;
    }

    /**
     * Get the last SOAP request XML (pretty-printed for debugging).
     */
    public function getLastRequest(): ?string
    {
        return $this->transport->getLastRequestFormatted();
    }

    /**
     * Get the last SOAP response XML (pretty-printed for debugging).
     */
    public function getLastResponse(): ?string
    {
        return $this->transport->getLastResponseFormatted();
    }

    /**
     * Get the session manager instance.
     */
    public function session(): SessionManager
    {
        return $this->sessionManager;
    }

    /**
     * Execute a standard stateful operation (most operations follow this pattern).
     * @throws OperationNotFoundException|SoapFaultException
     */
    protected function executeStandardOperation(string $operationName, array $body): AmadeusResponse
    {
        $metadata = $this->wsdlManager->getRegistry()->get($operationName);
        $soapBody = BodyBuilder::build($body, $metadata->rootElement);

        $isStateful = ! $this->sessionManager->isStatelessOperation($operationName);
        $hasSessionBody = $this->hasSessionBody($operationName) && $this->sessionManager->hasSession();

        return $this->executeOperation($operationName, $soapBody, $isStateful, $hasSessionBody);
    }

    /**
     * Core execution method.
     *
     * @throws SoapFaultException
     * @throws ConnectionException
     * @throws AuthenticationException
     * @throws XmlParseException
     * @throws SessionException
     * @throws OperationNotFoundException
     */
    protected function executeOperation(
        string $operationName,
        SoapVar $soapBody,
        bool $isStateful,
        bool $hasSessionBody,
    ): AmadeusResponse {
        $metadata = $this->wsdlManager->getRegistry()->get($operationName);

        // Only stateless calls are served from cache: a stateful response
        // carries the session that the next pricing/sell/PNR call continues.
        $cacheable = ! $isStateful && $this->cache?->isCacheable($operationName);

        // Keyed by the endpoint the request actually goes to: environments may
        // share a cache store, an office ID and even the WSDL directory path.
        $cacheKey = $metadata->serviceEndpoint."\n".$soapBody->enc_value;

        if ($cacheable && ($cachedXml = $this->cache->get($operationName, $cacheKey)) !== null) {
            // No SOAP exchange happened: getLastRequest()/getLastResponse() must not
            // keep exposing the previous call (possibly another user's, in workers)
            $this->transport->forgetLastExchange();

            return new AmadeusResponse($cachedXml, $metadata->responseNamespace);
        }

        // This call starts a new session (single-hotel search, PNR_Retrieve).
        // Replacing the stored one without signing it out would leave it open
        // on Amadeus until it times out, counting against the office's limit.
        if ($isStateful && ! $hasSessionBody && $this->sessionManager->hasSession()
            && ($this->config['session']['sign_out_replaced'] ?? true)) {
            $this->signOutReplacedSession();
        }

        $startedAt = microtime(true);

        OperationStarting::dispatch($operationName, $isStateful, $startedAt);

        try {
            $responseXml = $this->transport->call(
                $operationName,
                $soapBody,
                $metadata,
                $isStateful,
                $hasSessionBody,
            );
        } catch (\Throwable $e) {
            $this->failed($operationName, $e, $startedAt);
        }

        // Only pay the XML formatting cost (~5-10ms × 2) when logging
        // is actually enabled for this operation.
        if ($this->logger->shouldLog($operationName)) {
            $this->logger->logRequest($operationName, $this->transport->getLastRequestFormatted());
            $this->logger->logResponse($operationName, $this->transport->getLastResponseFormatted());
        }

        // Parse the response XML — throws XmlParseException on malformed XML
        try {
            $response = new AmadeusResponse($responseXml, $metadata->responseNamespace);
        } catch (XmlParseException $e) {
            $this->failed($operationName, $e, $startedAt);
        }

        // Detect session-level errors (expired/invalid) and throw early
        if ($response->hasSessionError()) {
            $this->sessionManager->clearSession();

            $sessionException = SessionException::expired($operationName);
            OperationFailed::dispatch($operationName, $sessionException, $startedAt, microtime(true));

            throw $sessionException;
        }

        if ($cacheable && ! $response->hasErrors()) {
            $this->cache->put($operationName, $cacheKey, $responseXml);
        }

        // Save session data from response
        $sessionData = $response->getSessionData();
        if ($sessionData !== null) {
            $this->sessionManager->saveSession($sessionData);
        }

        OperationCompleted::dispatch($operationName, $isStateful, $startedAt, microtime(true));

        return $response;
    }

    /**
     * Best-effort sign-out of the stored session before a new one replaces it.
     *
     * Never fails the call that is about to start: the stored session may
     * already have expired on Amadeus, so errors are reported and the
     * session is forgotten either way.
     */
    protected function signOutReplacedSession(): void
    {
        try {
            $this->signOut();
        } catch (\Throwable $e) {
            report($e);

            $this->sessionManager->clearSession();
        }
    }

    /**
     * Log a failed call, dispatch OperationFailed and rethrow.
     */
    protected function failed(string $operationName, \Throwable $e, float $startedAt): never
    {
        $this->logger->logError($operationName, $e);

        OperationFailed::dispatch($operationName, $e, $startedAt, microtime(true));

        throw $e;
    }

    /**
     * Configured defaults for hotelSearch(); explicit params override them.
     */
    protected function searchDefaults(): array
    {
        return array_filter([
            'search_cache_level' => $this->config['search_cache_level']['default'] ?? null,
            'rate_strategy' => $this->config['rate_filtering']['default_strategy'] ?? null,
        ]);
    }

    /**
     * Determine if an operation should include session body data.
     * Some operations (Hotel_MultiSingleAvailability, PNR_Retrieve) use
     * a Start session header even when a session exists.
     */
    protected function hasSessionBody(string $operation): bool
    {
        return ! in_array($operation, [
            'Hotel_MultiSingleAvailability',
            'PNR_Retrieve',
        ]);
    }
}
