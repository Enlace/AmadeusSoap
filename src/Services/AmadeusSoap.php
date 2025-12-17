<?php

namespace Aldogtz\AmadeusSoap\Services;

use Aldogtz\AmadeusSoap\WsdlAnalyser\InvalidWsdlFileException;
use DOMDocument;
use DOMException;
use DOMNode;
use DOMNodeList;
use DOMXPath;
use Exception;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Aldogtz\AmadeusSoap\SoapClient\SoapClient;
use Random\RandomException;
use SoapFault;
use SoapHeader;
use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;
use Throwable;
use Aldogtz\AmadeusSoap\WsdlAnalyser\WsdlAnalyser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redis;

/**
 * Class AmadeusSoap
 *
 * Provides a wrapper for Amadeus SOAP web services operations.
 *
 * @method static DOMXPath Hotel_MultiSingleAvailability(array $params = []) Performs hotel availability search for single or multiple properties
 * @method static DOMXPath Hotel_EnhancedPricing(array $params = []) Retrieves detailed pricing information for a specific hotel room rate
 * @method static DOMXPath Hotel_Sell(array $params = []) Creates a hotel reservation segment in the PNR
 * @method static DOMXPath Hotel_DescriptiveInfo(array $params = []) Retrieves descriptive information about hotel properties
 * @method static DOMXPath Hotel_CompleteReservationDetails(array $params = []) Retrieves complete details of a hotel reservation
 * @method static DOMXPath PNR_AddMultiElements(array $params = []) Adds multiple elements (passengers, data) to a PNR
 * @method static DOMXPath PNR_Retrieve(array $params = []) Retrieves a PNR by its record locator
 * @method static DOMXPath PNR_Cancel(array $params = []) Cancels elements or segments from a PNR
 * @method static DOMXPath Security_SignOut() Ends the current Amadeus session and clears session data
 *
 * @package Aldogtz\AmadeusSoap\Services
 */
class AmadeusSoap extends WsdlAnalyser
{
    protected static SoapClient $client;
    protected static mixed $username;
    protected static mixed $password;
    public static mixed $officeId;
    protected static array $msgAndVer = [];

    public function __construct(string $wsdlPath)
    {
        self::$username = config('amadeus-soap.username');
        self::$password = config('amadeus-soap.password');
        self::$officeId = config('amadeus-soap.officeId');

        $files = scandir($wsdlPath);

        $wsdls = Arr::where($files, function ($path) {
            return Str::endsWith($path, '.wsdl');
        });

        $wsdlPaths = Arr::map($wsdls, function ($path) use ($wsdlPath) {
            return $wsdlPath . DIRECTORY_SEPARATOR . $path;
        });

        self::$msgAndVer = self::loadMessagesAndVersions($wsdlPaths);
    }

    /**
     * @throws SoapFault
     */
    protected static function createClient(string $wsdlPath): SoapClient
    {
        return new SoapClient($wsdlPath, [
            'trace' => true,
            'exception' => true,
            'cache_wsdl' => WSDL_CACHE_MEMORY,
            'stream_context' => stream_context_create([
                'http' => [
                    'protocol_version' => '1.0',
                    'header' => 'Connection: Close'
                ]
            ]),
        ]);
    }

    /**
     * @throws Exception
     */
    public static function __callStatic(string $message, array $arguments)
    {
        if (!isset(self::$msgAndVer[$message])) {
            throw new Exception("Operation not defined in the wsld");
        }

        $path = self::getWsdlPath($message);

        self::$client = self::createClient($path);
        self::$client->__setUsernameToken(self::$username, self::$password);

        $params = self::createBodyParams(Arr::first($arguments, null, []), $message);

        try {
            self::$client->{$message}($params);
        } catch (Throwable $e) {
            $request = new DOMDocument('1.0', 'UTF-8');
            $request->formatOutput = true;
            $request->loadXML(self::$client->__getLastRequest());
            dd($request->saveXML(), $e);
        }

        if ($message == 'Security_SignOut') {
            $key = is_null(Auth::id()) ? 'system' : Auth::id();
            Redis::del("amadeusSession$key");
        }

        $responseObject = new DOMDocument('1.0', 'UTF-8');
        // dd($responseObject);
        $responseObject->loadXML(self::$client->__getLastResponse());
        $responseDomXpath = new DOMXPath($responseObject);
        $responseDomXpath->registerNamespace('res', self::getResponseRootElementNameSpace($message));
        // $responseDomXpath->registerNamespace("php", "http://php.net/xpath");
        // $responseDomXpath->registerPHPFunctions();

        $sessionData = self::getSessionParams($responseDomXpath);
        // dd($responseDomXpath);

        if (!empty($sessionData)) {
            $key = is_null(Auth::id()) ? 'system' : Auth::id();
            Redis::set("amadeusSession$key", json_encode($sessionData));
        }
        return $responseDomXpath;
    }

    protected static function getWsdlPath($message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        return self::$wsdlIds[$wsdlId];
    }

    protected static function setSoapHeaders(array $headers): void
    {
        self::$client->__setSoapHeaders([]);
        self::$client->__setSoapHeaders($headers);
    }

    /**
     * @throws RandomException
     * @throws DOMException
     */
    protected static function createHeaders(array $params = [], string $message): array
    {
        $headers = [];

        if (self::isStateful($params, $message)) {
            $headers[] = self::createSessionHeader($message);
        }

        $headers[] = self::createMessageIdHeader();
        $headers[] = self::createActionHeader($message);
        $headers[] = self::createToHeader($message);

        if (!self::sessionWithBody($message) || !self::isStateful($params, $message)) {
            $headers[] = self::createSecurityHeader();
            $headers[] = self::createAMASecurityHostedUserHeader();
        }

        return $headers;
    }

    /**
     * @throws DOMException
     */
    protected function createSessionHeader(string $message): SoapHeader
    {
        $body = [];
        $sessionBody = self::sessionWithBody($message);
        $key = is_null(Auth::id()) ? 'system' : Auth::id();
        $sessionData = json_decode(Redis::get("amadeusSession$key"));

        if ($sessionBody) {
            foreach ($sessionData as $key => $value) {
                if ($key == "sequenceNumber") {
                    (int)$value++;
                }
                $body["ses:" . ucfirst($key)] = $value;
            }
        }


        $arrayToXml = new ArrayToXml($body, [
            'rootElementName' => 'ses:Session',
            '_attributes' => ['xmlns:ses' => 'http://xml.amadeus.com/2010/06/Session_v3', 'TransactionStatusCode' => $sessionBody ? 'InSeries' : 'Start'],
        ]);

        $body = $arrayToXml->dropXmlDeclaration()->toXml();

        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Session_v3',
            'Session',
            new SoapVar($body, XSD_ANYXML)
        );
    }

    protected static function createMessageIdHeader(): SoapHeader
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'MessageID',
            (string)Str::uuid()
        );
    }

    protected static function createActionHeader(string $message): SoapHeader
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $action = self::$wsdlDomXpath[$wsdlId]->evaluate(sprintf('string(//wsdl:operation[./@name="%s"]/soap:operation/@soapAction)', $message));
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'Action',
            $action
        );
    }

    protected static function createToHeader(string $message): SoapHeader
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $To = self::$wsdlDomXpath[$wsdlId]->evaluate('string(/wsdl:definitions/wsdl:service/wsdl:port/soap:address/@location)');
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'To',
            $To
        );
    }

    /**
     * @throws RandomException
     */
    protected static function createSecurityHeader(): SoapHeader
    {
        $nonce = random_bytes(32);
        $encodedNonce = base64_encode($nonce);
        date_default_timezone_set("UTC");
        $timestamp = Carbon::now()->toIso8601String();
        $passSHA = base64_encode(sha1($nonce . $timestamp . sha1(self::$password, true), true));

        return new SoapHeader(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wsswssecurity-secext-1.0.xsd',
            'Security',
            new SoapVar('<oas:Security xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <oas:UsernameToken xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" oas1:Id="UsernameToken-1">
            <oas:Username>' . self::$username . '</oas:Username>
            <oas:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' . $encodedNonce . '</oas:Nonce>
            <oas:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">' . $passSHA . '</oas:Password>
            <oas1:Created>' . $timestamp . '</oas1:Created>
            </oas:UsernameToken>
            </oas:Security>', XSD_ANYXML)
        );
    }

    protected static function createAMASecurityHostedUserHeader(): SoapHeader
    {
        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Security_v1',
            'AMA_SecurityHostedUser',
            ["UserID" => [
                "_" => "",
                "POS_Type" => "1",
                "PseudoCityCode" => self::$officeId,
                "AgentDutyCode" => "SU",
                "RequestorType" => "U",
            ]]
        );
    }

    /**
     * @throws DOMException
     */
    protected static function createBodyParams(array $params = [], string $message): SoapVar
    {
        $attributes = [];

        if (count($params) > 1) {
            $attributes = array_splice($params, 1);
        } else {
            if (!empty($params)) {
                $params = $params[0];
            }
        }

        $arrayToXml = new ArrayToXml($params, [
            'rootElementName' => self::getRootElement($message),
            '_attributes' => $attributes,
        ]);

        $body = $arrayToXml->dropXmlDeclaration()->prettify()->toXml();

        return new SoapVar($body, XSD_ANYXML);
    }

    public static function evaluateXpathQueryOnWsdl($wsdlId, $wsdlFilePath, $xpath): DOMNodeList|DOMNode|string|null
    {
        try {
            WsdlAnalyser::loadWsdlXpath($wsdlFilePath, $wsdlId);
        } catch (InvalidWsdlFileException) {

        }

        $imports = self::$wsdlDomXpath[$wsdlId]->query(WsdlAnalyser::XPATH_IMPORTS);

        foreach ($imports as $import) {
            $importPath = realpath(dirname($wsdlFilePath)) . DIRECTORY_SEPARATOR . $import->value;
            $wsdlContent = file_get_contents($importPath);

            $importedDomDoc = new DOMDocument('1.0', 'UTF-8');
            $importedDomDoc->loadXML($wsdlContent);
            $importedDomXpath = new DOMXPath($importedDomDoc);

            $namespaces = $importedDomXpath->evaluate('//wsdl:definitions/namespace::*');
            $query = self::$wsdlDomXpath[$wsdlId]->evaluate("//wsdl:definitions/namespace::*");

            $baseNamespaces = iterator_to_array($query);
            $baseNamespaces = array_map(function ($namespace) {
                return $namespace->namespaceURI;
            }, $baseNamespaces);

            $importedNamespaces = iterator_to_array($namespaces);

            $missingNamespaces = array_filter($importedNamespaces, function ($namespace) use ($baseNamespaces) {
                return !in_array($namespace->namespaceURI, $baseNamespaces);
            });

            foreach ($missingNamespaces as $missingNamespace) {
                $root = self::$wsdlDomXpath[$wsdlId]->query('//wsdl:definitions')->item(0);
                $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:' . $missingNamespace->prefix, $missingNamespace->namespaceURI);
            }

            $xsImports = $importedDomXpath->query('//wsdl:definitions/wsdl:types/xs:schema/xs:import');
            foreach ($xsImports as $xsImport) {
                $node = self::$wsdlDomDoc[$wsdlId]->importNode($xsImport, true);
                $schemaNode = self::$wsdlDomDoc[$wsdlId]->getElementsByTagName('schema')->item(0);
                $schemaNode->appendChild($node);
            }

            $wsdlMessages = $importedDomXpath->query('//wsdl:definitions/wsdl:message');
            foreach ($wsdlMessages as $wsdlMessage) {
                $node = self::$wsdlDomDoc[$wsdlId]->importNode($wsdlMessage, true);
                $definitionsNode = self::$wsdlDomDoc[$wsdlId]->getElementsByTagName('definitions')->item(0);
                $definitionsNode->appendChild($node);
            }

            $portTypes = $importedDomXpath->query('//wsdl:definitions/wsdl:portType');
            foreach ($portTypes as $portType) {
                $node = self::$wsdlDomDoc[$wsdlId]->importNode($portType, true);
                $definitionsNode = self::$wsdlDomDoc[$wsdlId]->getElementsByTagName('definitions')->item(0);
                $definitionsNode->appendChild($node);
            }
        }

        return self::$wsdlDomXpath[$wsdlId]->evaluate($xpath);
    }

    protected static function getRootElement(string $message): string
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $messageName = self::$msgAndVer[$message]['messageName'];
        $rootElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    protected static function getResponseRootElement(string $message): string
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $messageName = self::$msgAndVer[$message]['outputMessageName'];
        $rootElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    public static function getResponseRootElementNameSpace(string $message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $rootElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:portType/wsdl:operation[@name='%s']/wsdl:output/@message)", $message));
        $messageName = explode(':', $rootElement)[1];
        $messageElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:definitions/wsdl:message[./@name = '%s']/wsdl:part/@element)", $messageName));
        $nsPrefix = explode(':', $messageElement)[0];
        $namespaces = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], "//wsdl:definitions/namespace::*");

        $namespaceNode = array_filter(iterator_to_array($namespaces), function ($namespace) use ($nsPrefix) {
            return $namespace->prefix == $nsPrefix;
        });
        return Arr::first($namespaceNode)->namespaceURI;
    }

    public static function getNamespace(string $message)
    {
        return self::getResponseRootElementNameSpace($message);
    }

    public static function isStateful(array $params, string $message): bool
    {
        if ($message == "Hotel_DescriptiveInfo") {
            return false;
        }

        if ($message == "Hotel_MultiSingleAvailability") {
            $body = new DOMDocument('1.0', 'UTF-8');
            $body->loadXML(Arr::first($params)->enc_value);
            $xpath = new DOMXPath($body);
            $hotelRefs = $xpath->evaluate('//AvailRequestSegments/AvailRequestSegment/HotelSearchCriteria/Criterion/HotelRef');

            if ($hotelRefs->length > 1) return true;

            foreach ($hotelRefs as $hotelRef) {
                if (!$hotelRef->hasAttribute('HotelCode') && $hotelRef->hasAttribute('HotelCityCode')) return false;
            }
        }

        return true;
    }

    protected static function multiKeyExists(array $arr, $key)
    {

        // is in base array?
        if (array_key_exists($key, $arr)) {
            return $arr[$key];
        }

        // check arrays contained in this array
        foreach ($arr as $element) {
            if (is_array($element)) {
                $result = self::multiKeyExists($element, $key);
                if ($result) {
                    return $result;
                }
            }
        }

        return false;
    }

    protected static function getSessionParams(DOMXPath $xml): array
    {
        if ($xml->evaluate('string(//awsse:Session/@TransactionStatusCode)') != "InSeries") {
            return [];
        }

        $sessionId = $xml->evaluate('string(//awsse:Session/awsse:SessionId)');
        $sequenceNumber = $xml->evaluate('string(//awsse:Session/awsse:SequenceNumber)');
        $securityToken = $xml->evaluate('string(//awsse:Session/awsse:SecurityToken)');

        return [
            "sessionId" => $sessionId,
            "sequenceNumber" => $sequenceNumber,
            "securityToken" => $securityToken,
        ];
    }

    public static function sessionWithBody(string $message): bool
    {
        if ($message != "Hotel_MultiSingleAvailability" && $message != "PNR_Retrieve") {
            return true;
        }
        return false;
    }

    /**
     * @throws Exception
     */
    public function HotelSearch($type = 'multi', $params = []): DOMXPath
    {
        $acceptedTypes = ['multi', 'single'];

        if (!in_array($type, $acceptedTypes)) {
            throw new Exception("Type must be either multi or single");
        }

        $defaultParams = [
            "start" => Carbon::now()->toDateString(),
            "end" => Carbon::now()->addDays(7)->toDateString(),
            "quantity" => "1",
            "is_per_room" => "true",
            "guest_count" => "1",
            "distance" => "15",
            "children" => [],
            "info_source" => "Distribution",
            "search_cache_level" => "Live",
            "max_responses" => "96",
            "rate_code" => "RAC"
        ];

        $HotelRefAttributes = [];

        $sanitizedParams = array_filter($params);

        $params = array_merge($defaultParams, $sanitizedParams);

        foreach ($params as $key => $value) {
            if (is_null($value) && $key != 'children') {
                throw new Exception("$key cannot be null");
            }
        }

        foreach ($params['children'] as $child) {
            if (!array_key_exists('age', $child) && !array_key_exists('count', $child)) {
                throw new Exception("Child age and count is required");
            }
        }

        $searchData = [];

        if (array_key_exists('latitude', $params) && array_key_exists('longitude', $params)) {

            $params['latitude'] = (string)$params['latitude'];
            $params['longitude'] = (string)$params['longitude'];
            $params['distance'] = (string)$params['distance'];

            if (Str::contains($params['latitude'], '.')) {
                $explodedString = explode('.', $params['latitude']);
                $explodedString[1] = strlen($explodedString[1]) == 5 ? $explodedString[1] : (strlen($explodedString[1]) > 5 ? substr($explodedString[1], 0, 5) : Str::padRight($explodedString[1], 5, 0));
                $params['latitude'] = implode('', $explodedString);
            }

            if (Str::contains($params['longitude'], '.')) {
                $explodedString = explode('.', $params['longitude']);
                $explodedString[1] = strlen($explodedString[1]) == 5 ? $explodedString[1] : (strlen($explodedString[1]) > 5 ? substr($explodedString[1], 0, 5) : Str::padRight($explodedString[1], 5, 0));
                $params['longitude'] = implode('', $explodedString);
            }

            $searchData['Position'] = [
                "_attributes" => [
                    "Latitude" => $params['latitude'],
                    "Longitude" => $params['longitude']
                ]

            ];

            $searchData['Radius'] = [
                "_attributes" => [
                    "Distance" => $params['distance'],
                    "DistanceMeasure" => "DIS",
                    "UnitOfMeasureCode" => "2"
                ]
            ];
        } else {
            if (array_key_exists('hotel_city_code', $params)) $HotelRefAttributes['HotelCityCode'] = $params['hotel_city_code'];
            if (array_key_exists('hotel_name', $params)) {
                $HotelRefAttributes['HotelName'] = $params['hotel_name'];
                $HotelRefAttributes['ExtendedCitySearchIndicator'] = '1';
            }
            if (array_key_exists('hotel_name', $params)) {
                $HotelRefAttributes['HotelName'] = $params['hotel_name'];
                $HotelRefAttributes['ExtendedCitySearchIndicator'] = '1';
            }
            if (array_key_exists('hotel_code', $params)) $HotelRefAttributes['HotelCode'] = $params['hotel_code'];
            if (array_key_exists('chain_code', $params)) $HotelRefAttributes['ChainCode'] = $params['chain_code'];

            $searchData['HotelRef'] = [
                '_attributes' => $HotelRefAttributes,
            ];
        }

        $GuestCount = [];

        $adults = [
            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $params['guest_count']],
        ];

        foreach ($params['children'] as $child) {
            $GuestCount[] = [
                '_attributes' => ['AgeQualifyingCode' => '8', 'Count' => $child['count'], 'Age' => $child['age']],
            ];
        }

        if ($params['children'] > 0) {
            $GuestCount[] = $adults;
        } else {
            $GuestCount = $adults;
        }

        $AvailRequestSegmentAttributes = [
            'InfoSource' => $params['info_source'],
        ];

        if (isset($params['more_data_echo_token']) && !isset($params['hotel_code'])) {
            $AvailRequestSegmentAttributes['MoreDataEchoToken'] = $params['more_data_echo_token'];
        }

        $body = [
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => $AvailRequestSegmentAttributes,
                    'HotelSearchCriteria' => [
                        'Criterion' => array_merge(['_attributes' => ['ExactMatch' => 'true']], $searchData)
                    ],
                ],
            ],
            'EchoToken' => 'MultiSingle',
            'Version' => '4.000',
            'PrimaryLangID' => 'EN',
            'SummaryOnly' => 'true',
            'AvailRatesOnly' => 'true',
            'RateRangeOnly' => 'true',
            'SearchCacheLevel' => $params['search_cache_level'],
            'RateDetailsInd' => 'true',
            'RequestedCurrency' => $params['currency'] ?? 'MXN',
            'MaxResponses' => $params['max_responses'],
            "ExactMatchOnly" => 'true'

        ];

        if (isset($params['sort_order'])) {
            $body['SortOrder'] = $params['sort_order'];
        }

        if ($type == 'multi' && !isset($params['hotel_name'])) {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['_attributes'] = ['AvailableOnlyIndicator' => 'true', 'BestOnlyIndicator' => 'true'];
        }

        if (isset($params['rating']) && !isset($params['hotel_code'])) {
            if ($params['rating'] == 5) {
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = [
                    '_attributes' => ['Provider' => 'LSR', 'Rating' => $params['rating']],
                ];
            } else {
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = [];

                for ($i = $params['rating']; $i <= 5; $i++) {
                    $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'][] = [
                        '_attributes' => ['Provider' => 'LSR', 'Rating' => "$i"],
                    ];
                }
            }
        }

        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['StayDateRange'] = [
            '_attributes' => ['Start' => $params['start'], 'End' => $params['end']],
        ];

        if (!isset($params['hotel_name']) && isset($params['rate_code'])) {
            $ratePlanCodes = is_array($params['rate_code']) ? $params['rate_code'] : [$params['rate_code']];
            $ratePlanCandidate = array_map(function ($ratePlanCode) {
                return [
                    '_attributes' => ['RatePlanCode' => $ratePlanCode],
                ];
            }, $ratePlanCodes);
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RatePlanCandidates'] = [
                'RatePlanCandidate' => $ratePlanCandidate,
            ];
        }

        if ((isset($params['max_rate']) || isset($params['min_rate'])) && !isset($params['hotel_code'])) {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RateRange'] = [
                '_attributes' => [
                    'CurrencyCode' => $params['currency'] ?? 'MXN',
                    'MaxRate' => $params['max_rate'],
                    'MinRate' => $params['min_rate'] ?? "0",
                ],
            ];
        }

        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RoomStayCandidates'] = [
            'RoomStayCandidate' => [
                '_attributes' => ['RoomID' => '1', 'Quantity' => $type == 'multi' ? "1" : $params['quantity']],
                'GuestCounts' => [
                    '_attributes' => ['IsPerRoom' => "true"],
                    'GuestCount' => $GuestCount,
                ]
            ]
        ];

        return self::Hotel_MultiSingleAvailability($body);
    }

    /**
     * @throws Exception
     */
    public function hotelPricing(array $params = []): DOMXPath
    {
        $requiredParams = [
            "start",
            "end",
            "hotel_code",
            "rate_plan_code",
            "booking_code",
            "room_type_code",
            "quantity",
            "is_per_room",
            "guest_count",
        ];

        foreach ($requiredParams as $param) {
            if (!array_key_exists($param, $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[$param])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        if (isset($params['children'])) {
            foreach ($params['children'] as $child) {
                if (!array_key_exists('age', $child) && !array_key_exists('count', $child)) {
                    throw new Exception("Child age and count is required");
                }
            }
        }

        $GuestCount = [];

        $adults = [
            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $params['guest_count']],
        ];

        if (isset($params['children'])) {
            foreach ($params['children'] as $child) {
                $GuestCount[] = [
                    '_attributes' => ['AgeQualifyingCode' => '8', 'Count' => $child['count'], 'Age' => $child['age']],
                ];
            }
        }

        if (isset($params['children']) && count($params['children']) > 0) {
            $GuestCount[] = $adults;
        } else {
            $GuestCount = $adults;
        }

        return self::Hotel_EnhancedPricing([
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => ['InfoSource' => 'Distribution'],
                    'HotelSearchCriteria' => [
                        'Criterion' => [
                            '_attributes' => ['ExactMatch' => 'true'],
                            'HotelRef' => [
                                '_attributes' => ['HotelCode' => $params['hotel_code']],
                            ],
                            'StayDateRange' => [
                                '_attributes' => ['Start' => $params['start'], 'End' => $params['end']],
                            ],
                            'RatePlanCandidates' => [
                                'RatePlanCandidate' => [
                                    '_attributes' => ['RatePlanCode' => $params['rate_plan_code']],
                                ]
                            ],
                            'RoomStayCandidates' => [
                                'RoomStayCandidate' => [
                                    '_attributes' => ['BookingCode' => $params['booking_code'], 'RoomTypeCode' => $params['room_type_code'], 'RoomID' => '1', 'Quantity' => $params['quantity']],
                                    'GuestCounts' => [
                                        '_attributes' => ['IsPerRoom' => $params['is_per_room']],
                                        'GuestCount' => $GuestCount,
                                    ]
                                ]
                            ],
                        ]
                    ],
                ],
            ],
            'EchoToken' => 'Pricing',
            'Version' => '4.000',
            'PrimaryLangID' => 'EN',
            'SummaryOnly' => 'false',
            'RateRangeOnly' => 'false',
            'RequestedCurrency' => 'MXN',
        ]);
    }

    protected function isMultiArray($a): bool
    {
        foreach ($a as $v) if (is_array($v)) return TRUE;
        return FALSE;
    }

    /**
     * @throws Exception
     */
    public function addMultiElements($type = "create", $params = [], $remarks = []): DOMXPath
    {
        $acceptedTypes = ['create', 'end', 'cancel'];

        $rfTexts = [
            'create' => 'Added via WebService',
            'end' => 'hotel reservation via WebServices',
            'cancel' => 'hotel CANCELLED via WebServices',
        ];

        if (!in_array($type, $acceptedTypes)) {
            throw new Exception("Method Not Supported");
        }

        $requiredParams = $type == 'create' ? [
            "name",
            "surname",
            "type",
        ] : [];

        $isMultiDimensional = self::isMultiArray($params);

        if ($isMultiDimensional) {
            foreach ($params as $index => $passenger) {
                foreach ($requiredParams as $param) {
                    if (!array_key_exists($param, $passenger)) {
                        throw new Exception("The param $param is required on passenger number $index");
                    }

                    if (empty($passenger[$param])) {
                        throw new Exception("The param $param cannot be null on passenger number $index");
                    }
                }
            }
        } else {
            foreach ($requiredParams as $param) {
                if (!array_key_exists($param, $params)) {
                    throw new Exception("The param $param is required");
                }

                if (empty($params[$param])) {
                    throw new Exception("The param $param cannot be null");
                }
            }
        }

        // HARDCODED: Valores fijos para retention line
        $retentionMonths = 6;  // Siempre 6 meses
        $cityCode = 'MTY';     // Siempre Monterrey
        $freeText = 'HOTEL BOOKING RETENTION';

        // Calcular passenger_count automáticamente
        $passengerCount = $isMultiDimensional ? count($params) : 1;

        // Buscar check_out_date en el primer pasajero
        $checkOutDate = null;
        if ($isMultiDimensional && isset($params[0]['check_out_date'])) {
            $checkOutDate = $params[0]['check_out_date'];
        }

        // Calcular fecha de retención
        if ($checkOutDate) {
            // Con check_out_date: checkout + 7 días + 6 meses
            $baseDate = \Carbon\Carbon::parse($checkOutDate)->addDays(7);
            $retentionDate = $baseDate->copy()->addMonths($retentionMonths);

            // VALIDAR límite de 361 días desde HOY (límite de Amadeus)
            $maxDate = \Carbon\Carbon::now()->addDays(361);
            if ($retentionDate->greaterThan($maxDate)) {
                $retentionDate = $maxDate;
            }
        } else {
            // Sin check_out_date: solo hoy + 7 días (tiempo normal, sin extensión)
            $retentionDate = \Carbon\Carbon::now()->addDays(7);
        }

        // Formato DDMMYY para Amadeus: 03OCT23 -> 031023
        $formattedDate = $retentionDate->format('dmy');



        $body = [];

        $body['pnrActions'] = [
            'optionCode' => $type == 'create' ? '0' : '11'
        ];

        if ($type == 'create') {
            $body['travellerInfo'] = [];
        }

        $dataElementsMaster = [
            'marker1' => null,
            'dataElementsIndiv' => []
        ];

        $receiveFrom = [
            'elementManagementData' => [
                'segmentName' => 'RF'
            ],
            'freetextData' => [
                'freetextDetail' => [
                    'subjectQualifier' => '3',
                    'type' => 'P22'
                ],
                'longFreetext' => $rfTexts[$type]
            ]
        ];

        if ($type == 'create') {

            $body['originDestinationDetails'] = [
                'originDestination' => [],  // CRÍTICO: vacío pero requerido
                'itineraryInfo' => [
                    'elementManagementItinerary' => [
                        'segmentName' => 'RU'  // RU = Miscellaneous/Retention segment
                    ],
                    'airAuxItinerary' => [  // CRÍTICO: todo va dentro de airAuxItinerary
                        'travelProduct' => [
                            'product' => [
                                'depDate' => $formattedDate  // Fecha hasta que el PNR estará activo
                            ],
                            'boardpointDetail' => [
                                'cityCode' => $cityCode  // Cualquier ciudad, usualmente mismo que officeId
                            ],
                            'company' => [
                                'identification' => '1A'  // Siempre 1A (Amadeus)
                            ]
                        ],
                        'messageAction' => [  // CORRECTO: messageAction (no itineraryMessageAction)
                            'business' => [
                                'function' => '32'  // Function code para retention
                            ]
                        ],
                        'relatedProduct' => [
                            'quantity' => $passengerCount,
                            'status' => 'HK'  // HK = Have Kept (Confirmed)
                        ],
                        'freetextItinerary' => [  // Opcional pero recomendado
                            'freetextDetail' => [
                                'subjectQualifier' => '3'
                            ],
                            'longFreetext' => $freeText  // Hasta 199 caracteres
                        ]
                    ]
                ]
            ];


            if ($isMultiDimensional) {
                foreach ($params as $key => $value) {
                    $body['travellerInfo'][] = [
                        'elementManagementPassenger' => [
                            'reference' => [
                                'qualifier' => 'PR',
                                'number' => $key + 1
                            ],
                            'segmentName' => 'NM'
                        ],
                        'passengerData' => [
                            'travellerInformation' => [
                                'traveller' => [
                                    'surname' => $value['surname']
                                ],
                                'passenger' => [
                                    'firstName' => $value['name'],
                                    'type' => $value['type']
                                ]
                            ]
                        ]
                    ];
                }
            } else {
                $body['travellerInfo'] = [
                    'elementManagementPassenger' => [
                        'reference' => [
                            'qualifier' => 'PR',
                            'number' => '1'
                        ],
                        'segmentName' => 'NM'
                    ],
                    'passengerData' => [
                        'travellerInformation' => [
                            'traveller' => [
                                'surname' => $params['surname']
                            ],
                            'passenger' => [
                                'firstName' => $params['name'],
                                'type' => $params['type']
                            ]
                        ]
                    ]
                ];
            }

            $body['dataElementsMaster'] = $dataElementsMaster;

            $body['dataElementsMaster']['dataElementsIndiv'][] = [
                'elementManagementData' => [
                    'reference' => [
                        'qualifier' => 'OT',
                        'number' => '1'
                    ],
                    'segmentName' => 'AP'
                ],
                'freetextData' => [
                    'freetextDetail' => [
                        'subjectQualifier' => '3',
                        'type' => 'P02',
                    ],
                    'longFreetext' => 'desarollo@enlaceforte.com'
                ]
            ];

            $body['dataElementsMaster']['dataElementsIndiv'][] = $receiveFrom;

            // Segmentos RM - Loyalty Program Comments
            $rmCount = 0;

            if (is_array($remarks) && isset($remarks['loyalty_programs']) && is_array($remarks['loyalty_programs'])) {
                foreach ($remarks['loyalty_programs'] as $loyaltyComment) {
                    if (!empty($loyaltyComment) && is_string($loyaltyComment)) {
                        $rmCount++;
                        $rmNumber = 2 + $rmCount;

                        $body['dataElementsMaster']['dataElementsIndiv'][] = [
                            'elementManagementData' => [
                                'reference' => [
                                    'qualifier' => 'OT',
                                    'number' => (string) $rmNumber
                                ],
                                'segmentName' => 'RM'
                            ],
                            'extendedRemark' => [
                                'structuredRemark' => [
                                    'type' => 'RM',
                                    'freetext' => $loyaltyComment
                                ]
                            ]
                        ];
                    }
                }
            }

            // Segmento TK - número ajustado dinámicamente según cantidad de RM
            $tkNumber = 2 + $rmCount + 1; // Si hay 2 RM: AP(1), RF(2), RM(3), RM(4), TK(5)
            $body['dataElementsMaster']['dataElementsIndiv'][] = [
                'elementManagementData' => [
                    'reference' => [
                        'qualifier' => 'OT',
                        'number' => (string) $tkNumber
                    ],
                    'segmentName' => 'TK'
                ],
                'ticketElement' => [
                    'ticket' => [
                        'indicator' => 'OK',
                    ],
                ]
            ];
        } else {
            $body['dataElementsMaster'] = $dataElementsMaster;
            foreach ($receiveFrom as $key => $value) {
                $body['dataElementsMaster']['dataElementsIndiv'][$key] = $value;
            }
        }

        return self::PNR_AddMultiElements([$body]);
    }
    protected function isMultiArrayWithException($a, $exceptions = []): bool
    {
        foreach ($a as $k => $v) {
            if (is_array($v) && !array_key_exists($k, array_flip($exceptions))) return true;
        }
        return false;
    }

    /**
     * @throws Exception
     */
    public function hotelSell($params = []): DOMXPath
    {
        $requiredParams = [
            "travelAgentRef"
        ];

        $passengerReferenceParams = [
            "value",
            "type"
        ];

        $roomStayDataParams = [
            "chainCode",
            "cityCode",
            "hotelCode",
            "passengerReference",
            "paymentType",
            "bookingCode",
            "ccHolderName",
            "vendorCode",
            "cardNumber",
            "securityId",
            "expiryDate",
        ];

        $isMultiDimensional = self::isMultiArrayWithException($params, [
            "passengerReference",
        ]);

        if (!$isMultiDimensional) $requiredParams = array_merge($requiredParams, $roomStayDataParams);

        foreach ($requiredParams as $param) {
            if (!array_key_exists($param, $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[$param])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        if ($isMultiDimensional) {
            foreach ($params as $index => $roomData) {
                if ($index != "travelAgentRef") {
                    $missingParams = array_diff_key(array_flip($roomStayDataParams), $roomData);

                    if (count($missingParams) > 0) {
                        $missingParamsStrings = implode(", ", array_keys($missingParams));
                        throw new Exception("The params $missingParamsStrings are required on room data number " . ($index + 1));
                    }

                    $passengerReferences = $roomData['passengerReference'];
                    if (is_array($passengerReferences)) {
                        foreach ($passengerReferences as $passengerReference) {
                            $missingPassengerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReference);
                            if (count($missingPassengerReferenceParams) > 0) {
                                $missingParamsStrings = implode(", ", array_keys($missingPassengerReferenceParams));
                                throw new Exception("The params $missingParamsStrings are required on room data number " . ($index + 1));
                            }
                        }
                    } else {
                        $missingPassengerReferenceParams = array_diff_key(array_flip($passengerReferenceParams, $passengerReferences));
                        if (count($missingPassengerReferenceParams) > 0) {
                            $missingParamsStrings = implode(", ", array_keys($missingPassengerReferenceParams));
                            throw new Exception("The params $missingParamsStrings are required on room data number " . ($index + 1));
                        }
                    }
                }
            }
        } else {
            $passengerReferences = $params['passengerReference'];
            if (is_array($passengerReferences)) {
                foreach ($passengerReferences as $passengerReference) {
                    $missingPassengerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReference);
                    if (count($missingPassengerReferenceParams) > 0) {
                        $missingParamsStrings = implode(", ", array_keys($missingPassengerReferenceParams));
                        throw new Exception("The params $missingParamsStrings are required on room data");
                    }
                }
            } else {
                $missingPassengerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReferences);
                if (count($missingPassengerReferenceParams) > 0) {
                    $missingParamsStrings = implode(", ", array_keys($missingPassengerReferenceParams));
                    throw new Exception("The params $missingParamsStrings are required on room data");
                }
            }
        }

        $body = [
            'systemIdentifier' => [
                'deliveringSystem' => [
                    'companyId' => 'WEBS'
                ]
            ],
            'travelAgentRef' => [
                'status' => 'APE',
                'reference' => [
                    'type' => 'OT',
                    'value' => $params['travelAgentRef'],
                ],
            ],
            'roomStayData' => []
        ];


        if (!$isMultiDimensional) {
            $representativeParties = [];
            $guestList = [];

            if (is_array($params['passengerReference'])) {
                foreach ($params['passengerReference'] as $passenger) {

                    $representativeParties[] = [
                        'occupantList' => [
                            'passengerReference' => [
                                'type' => $passenger['type'],
                                'value' => $passenger['value']
                            ]
                        ]
                    ];

                    $guestList[] = [
                        'occupantList' => [
                            'passengerReference' => [
                                'type' => $passenger['type'] == "BHO" ? 'RMO' : 'ROP',
                                'value' => $passenger['value']
                            ]
                        ]
                    ];
                }
            } else {
                $representativeParties = [
                    'occupantList' => [
                        'passengerReference' => [
                            'type' => $params['passengerReference']['type'],
                            'value' => $params['passengerReference']['value']
                        ]
                    ]
                ];
                $guestList = [
                    'occupantList' => [
                        'passengerReference' => [
                            'type' => $params['passengerReference']['type'] == "BHO" ? 'RMO' : 'ROP',
                            'value' => $params['passengerReference']['value']
                        ]
                    ]
                ];
            }

            $body['roomStayData'] = [
                'markerRoomStayData' => null,
                'globalBookingInfo' => [
                    'markerGlobalBookingInfo' => [
                        'hotelReference' => [
                            'chainCode' => (string)$params['chainCode'],
                            'cityCode' => (string)$params['cityCode'],
                            'hotelCode' => substr((string)$params['hotelCode'], -3)
                        ],

                    ],
                    'representativeParties' => $representativeParties
                ],
                'roomList' => [
                    'markerRoomstayQuery' => null,
                    'roomRateDetails' => [
                        'marker' => null,
                        'hotelProductReference' => [
                            'referenceDetails' => [
                                'type' => 'BC',
                                'value' => $params['bookingCode']
                            ]
                        ],
                        'markerOfExtra' => null
                    ],
                    'guaranteeOrDeposit' => [
                        'paymentInfo' => [
                            'paymentDetails' => [
                                'formOfPaymentCode' => '1',
                                'paymentType' => $params['paymentType'],
                                'serviceToPay' => '3'
                            ]
                        ],
                        'groupCreditCardInfo' => [
                            'creditCardInfo' => [
                                'ccInfo' => [
                                    'vendorCode' => $params['vendorCode'],
                                    'cardNumber' => $params['cardNumber'],
                                    'securityId' => $params['securityId'],
                                    'expiryDate' => $params['expiryDate'],
                                    'ccHolderName' => $params['firstName'] . ' ' . $params['surname'],
                                    'surname' => $params['surname'],
                                    'firstName' => $params['firstName'],
                                ]
                            ]
                        ],
                    ],
                    'guestList' => $guestList
                ]
            ];
        } else {
            foreach ($params as $key => $param) {
                if ($key != "travelAgentRef") {
                    $representativeParties = [];
                    $guestList = [];

                    if (is_array($param['passengerReference'])) {
                        foreach ($param['passengerReference'] as $passenger) {

                            $representativeParties[] = [
                                'occupantList' => [
                                    'passengerReference' => [
                                        'type' => $passenger['type'],
                                        'value' => $passenger['value']
                                    ]
                                ]
                            ];

                            $guestList[] = [
                                'occupantList' => [
                                    'passengerReference' => [
                                        'type' => $passenger['type'] == "BHO" ? 'RMO' : 'ROP',
                                        'value' => $passenger['value']
                                    ]
                                ]
                            ];
                        }
                    } else {
                        $representativeParties = [
                            'occupantList' => [
                                'passengerReference' => [
                                    'type' => $param['passengerReference']['type'],
                                    'value' => $param['passengerReference']['value']
                                ]
                            ]
                        ];
                        $guestList = [
                            'occupantList' => [
                                'passengerReference' => [
                                    'type' => $param['passengerReference']['type'] == "BHO" ? 'RMO' : 'ROP',
                                    'value' => $param['passengerReference']['value']
                                ]
                            ]
                        ];
                    }

                    $body['roomStayData'][] = [
                        'markerRoomStayData' => null,
                        'globalBookingInfo' => [
                            'markerGlobalBookingInfo' => [
                                'hotelReference' => [
                                    'chainCode' => (string)$param['chainCode'],
                                    'cityCode' => (string)$param['cityCode'],
                                    'hotelCode' => substr((string)$param['hotelCode'], -3)
                                ],

                            ],
                            'representativeParties' => $representativeParties
                        ],
                        'roomList' => [
                            'markerRoomstayQuery' => null,
                            'roomRateDetails' => [
                                'marker' => null,
                                'hotelProductReference' => [
                                    'referenceDetails' => [
                                        'type' => 'BC',
                                        'value' => $param['bookingCode']
                                    ]
                                ],
                                'markerOfExtra' => null
                            ],
                            'guaranteeOrDeposit' => [
                                'paymentInfo' => [
                                    'paymentDetails' => [
                                        'formOfPaymentCode' => '1',
                                        'paymentType' => $param['paymentType'],
                                        'serviceToPay' => '3'
                                    ]
                                ],
                                'groupCreditCardInfo' => [
                                    'creditCardInfo' => [
                                        'ccInfo' => [
                                            'vendorCode' => $param['vendorCode'],
                                            'cardNumber' => $param['cardNumber'],
                                            'securityId' => $param['securityId'],
                                            'expiryDate' => $param['expiryDate'],
                                            'ccHolderName' => $param['ccHolderName'],
                                        ]
                                    ]
                                ],
                            ],
                            'guestList' => $guestList
                        ]
                    ];
                }
            }
        }

        return self::Hotel_Sell([$body]);
    }

    public function singOut(): DOMXPath
    {
        return self::Security_SignOut();
    }

    /**
     * @throws Exception
     */
    public function hotelDescriptiveInfo(array $params = []): DOMXPath
    {
        $requiredParams = ["hotelCode"];

        $defaultParams = [
            'hotelCode' => [],
            'hotelSendData' => 'true',
            'contactSendData' => 'true',
            'multimediaSendData' => 'true',
            'sendGuestRooms' => 'true',
            'sendMeetingRooms' => 'true',
            'sendRestaurants' => 'true',
            'sendPolicies' => 'true',
            'sendAttractions' => 'true',
            'sendRefPoints' => 'true',
            'sendRecreations' => 'true',
            'sendAwards' => 'true',
            'sendLoyalPrograms' => 'true',

        ];

        foreach ($requiredParams as $param) {
            if (!array_key_exists(lcfirst(ucwords($param)), $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[lcfirst(ucwords($param))])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        $HotelDescriptiveInfo = [];

        $params = array_merge($defaultParams, $params);

        if (!is_array($params['hotelCode'])) {
            $HotelDescriptiveInfo = [
                '_attributes' => ['HotelCode' => $params['hotelCode']],
                'HotelInfo' => [
                    '_attributes' => ['SendData' => $params['hotelSendData']]
                ],
                'FacilityInfo' => [
                    '_attributes' => ['SendGuestRooms' => $params['sendGuestRooms'], 'SendMeetingRooms' => $params['sendMeetingRooms'], 'SendRestaurants' => $params['sendRestaurants']]
                ],
                'Policies' => [
                    '_attributes' => ['SendPolicies' => $params['sendPolicies']],
                ],
                'AreaInfo' => [
                    '_attributes' => ['SendAttractions' => $params['sendAttractions'], 'SendRefPoints' => $params['sendRefPoints'], 'SendRecreations' => $params['sendRecreations']],
                ],
                'AffiliationInfo' => [
                    '_attributes' => ['SendAwards' => $params['sendAwards'], 'SendLoyalPrograms' => $params['sendLoyalPrograms']],
                ],
                'ContactInfo' => [
                    '_attributes' => ['SendData' => $params['contactSendData']],
                ],
                'MultimediaObjects' => [
                    '_attributes' => ['SendData' => $params['multimediaSendData']],
                ],
                'ContentInfos' => [
                    'ContentInfo' => [
                        '_attributes' => ['Name' => 'SecureMultimediaURLs'],
                    ]
                ]
            ];
        } else {
            foreach ($params['hotelCode'] as $hotelCode) {
                $HotelDescriptiveInfo[] = [
                    '_attributes' => ['HotelCode' => $hotelCode],
                    'HotelInfo' => [
                        '_attributes' => ['SendData' => $params['hotelSendData']]
                    ],
                    'FacilityInfo' => [
                        '_attributes' => ['SendGuestRooms' => $params['sendGuestRooms'], 'SendMeetingRooms' => $params['sendMeetingRooms'], 'SendRestaurants' => $params['sendRestaurants']]
                    ],
                    'Policies' => [
                        '_attributes' => ['SendPolicies' => $params['sendPolicies']],
                    ],
                    'AreaInfo' => [
                        '_attributes' => ['SendAttractions' => $params['sendAttractions'], 'SendRefPoints' => $params['sendRefPoints'], 'SendRecreations' => $params['sendRecreations']],
                    ],
                    'AffiliationInfo' => [
                        '_attributes' => ['SendAwards' => $params['sendAwards'], 'SendLoyalPrograms' => $params['sendLoyalPrograms']],
                    ],
                    'ContactInfo' => [
                        '_attributes' => ['SendData' => $params['contactSendData']],
                    ],
                    'MultimediaObjects' => [
                        '_attributes' => ['SendData' => $params['multimediaSendData']],
                    ],
                    'ContentInfos' => [
                        'ContentInfo' => [
                            '_attributes' => ['Name' => 'SecureMultimediaURLs'],
                        ]
                    ]
                ];
            }
        }

        return self::Hotel_DescriptiveInfo([
            'HotelDescriptiveInfos' => [
                'HotelDescriptiveInfo' => $HotelDescriptiveInfo,
            ],
            'EchoToken' => 'withParsing',
            'Version' => '6.001',
            'PrimaryLangID' => 'en',
        ]);
    }

    public function getLastRequest(): bool|string
    {
        $dom = new DOMDocument('1.0');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = true;
        $dom->loadXML(self::$client->__getLastRequest());
        return $dom->saveXML();
    }

    public function getLastResponse(): bool|string
    {
        $dom = new DOMDocument('1.0');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = true;
        $dom->loadXML(self::$client->__getLastResponse());
        return $dom->saveXML();
    }

    /**
     * @throws Exception
     */
    public function pnrRetrieve(array $params = []): DOMXPath
    {

        if (empty($params['pnrNumber'])) {
            throw new Exception("The param pnrNumber is required");
        }

        return self::PNR_Retrieve([
            [
                "retrievalFacts" => [
                    "retrieve" => [
                        "type" => "2"
                    ],
                    "reservationOrProfileIdentifier" => [
                        "reservation" => [
                            "controlNumber" => $params['pnrNumber']
                        ]
                    ]
                ]
            ]
        ]);
    }

    /**
     * @throws Exception
     */
    public function hotelCompleteReservationDetails(array $params = []): DOMXPath
    {

        $requiredParams = [
            "pnrNumber",
            "segmentNumber"
        ];

        $missingParams = array_diff($requiredParams, array_keys($params));

        if (!empty($missingParams)) {
            throw new Exception("The params " . implode(', ', $missingParams) . " are required");
        }

        return self::Hotel_CompleteReservationDetails([
            [
                "retrievalKeyGroup" => [
                    "retrievalKey" => [
                        "reservation" => [
                            "companyId" => '1A',
                            "controlNumber" => $params['pnrNumber'],
                            "controlType" => "P",
                        ]
                    ],
                    "tattooID" => [
                        "referenceDetails" => [
                            "type" => "S",
                            "value" => $params['segmentNumber']
                        ]
                    ]
                ],
            ]
        ]);
    }

    /**
     * @throws Exception
     */
    public function pnrCancel(array $params = []): DOMXPath
    {
        $requiredParams = [
            "segmentNumber"
        ];

        $missingParams = array_diff($requiredParams, array_keys($params));

        if (!empty($missingParams)) {
            throw new Exception("The params " . implode(', ', $missingParams) . " are required");
        }

        $cancelElements = [];

        if (is_array($params['segmentNumber'])) {
            foreach ($params['segmentNumber'] as $segmentNumber) {
                $cancelElements[] = [
                    "entryType" => "E",
                    "element" => [
                        "identifier" => "ST",
                        "number" => $segmentNumber
                    ]
                ];
            }
        } else {
            $cancelElements = [
                "entryType" => "E",
                "element" => [
                    "identifier" => "ST",
                    "number" => $params['segmentNumber']
                ]
            ];
        }

        return self::PNR_Cancel([
            [
                "pnrActions" => [
                    "optionCode" => "0"
                ],
                "cancelElements" => $cancelElements
            ]
        ]);
    }


    /**
     * @throws Exception
     */
    public function recursiveHotelSearch($type = 'multi', array $params): DOMXPath|RedirectResponse
    {
        $response = $this->HotelSearch('multi', $params);
        $hasHotelStays = !empty($response->evaluate("count(//res:Warnings/res:Warning[./@Tag='OK'])"));
        $moreIndicator = $response->evaluate("string(//res:RoomStays/@MoreIndicator)");

        if (!empty($params['more_data_echo_token']) && !empty($moreIndicator)) {
            return $response;
        }

        if (!$hasHotelStays) {

            if (!empty($moreIndicator)) {

                return $this->recursiveHotelSearch('multi', [...$params, "MoreDataEchoToken" => $moreIndicator]);
            }
            // dd($hotels, $response, AmadeusSoapFacade::getLastRequest());

            return redirect()->back()->withErrors([
                "search" => "No se encontraron hoteles con los criterios de búsqueda seleccionados."
            ]);
        }

        return $response;
    }
}
