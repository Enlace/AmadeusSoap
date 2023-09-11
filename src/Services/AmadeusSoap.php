<?php

namespace Aldogtz\AmadeusSoap\Services;

use DOMDocument;
use DOMXPath;
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Aldogtz\AmadeusSoap\SoapClient\SoapClient;
use SoapHeader;
use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;
use Throwable;
use Aldogtz\AmadeusSoap\WsdlAnalyser\WsdlAnalyser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redis;

class AmadeusSoap extends WsdlAnalyser
{
    protected static $client;
    protected static $username;
    protected static $password;
    public static $officeId;
    protected static $msgAndVer = [];

    public function __construct(String $wsdlPath)
    {
        self::$username = config('amadeus-soap.username');
        self::$password = config('amadeus-soap.password');
        self::$officeId = config('amadeus-soap.officeId');

        $files = scandir(storage_path($wsdlPath));

        $wsdls = Arr::where($files, function ($path,) {
            return Str::endsWith($path, '.wsdl');
        });

        $wsdlPaths = Arr::map($wsdls, function ($path) use ($wsdlPath) {
            return storage_path($wsdlPath . DIRECTORY_SEPARATOR . $path);
        });

        self::$msgAndVer = self::loadMessagesAndVersions($wsdlPaths);
        // dd(self::$msgAndVer, self::$wsdlIds);
    }

    protected static function createClient(String $wsdlPath)
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
            $response = self::$client->{$message}($params);
        } catch (Throwable $e) {
            dd($e);
            $request = new DOMDocument('1.0', 'UTF-8');
            $request->formatOutput = true;
            $request->loadXML(self::$client->__getLastRequest());
            dd($request->saveXML(), $e);
        }

        if ($message == 'Security_SignOut') {
            Redis::del('amadeusSession'. Auth::user()->id);
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
            Redis::set('amadeusSession'. Auth::user()->id, json_encode($sessionData));
        }
        return $responseDomXpath;
    }

    protected static function getWsdlPath($message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        return self::$wsdlIds[$wsdlId];
    }

    protected static function setSoapHeaders(array $headers)
    {
        self::$client->__setSoapHeaders([]);
        self::$client->__setSoapHeaders($headers);
    }

    protected static function createHeaders(array $params = [], String $message)
    {
        $headers = [];

        if (self::isStateful($params, $message)) {
            array_push($headers, self::createSessionHeader($message));
        }

        array_push($headers, self::createMessageIdHeader());
        array_push($headers, self::createActionHeader($message));
        array_push($headers, self::createToHeader($message));

        if (!self::sessionWithBody($message) || !self::isStateful($params, $message)) {
            array_push($headers, self::createSecurityHeader());
            array_push($headers, self::createAMASecurityHostedUserHeader());
        }

        return $headers;
    }

    protected function createSessionHeader(String $message)
    {
        $body = [];
        $sessionBody = self::sessionWithBody($message);
        $sessionData = json_decode(Redis::get('amadeusSession'. Auth::user()->id));

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

    protected static function createMessageIdHeader()
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'MessageID',
            (string) Str::uuid()
        );
    }

    protected static function createActionHeader(String $message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $action = self::$wsdlDomXpath[$wsdlId]->evaluate(sprintf('string(//wsdl:operation[./@name="%s"]/soap:operation/@soapAction)', $message));
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'Action',
            $action
        );
    }

    protected static function createToHeader(String $message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $To = self::$wsdlDomXpath[$wsdlId]->evaluate('string(/wsdl:definitions/wsdl:service/wsdl:port/soap:address/@location)');
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'To',
            $To
        );
    }

    protected static function createSecurityHeader()
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

    protected static function createAMASecurityHostedUserHeader()
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

    protected static function createBodyParams(array $params = [], string $message)
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

    public static function evaluateXpathQueryOnWsdl($wsdlId, $wsdlFilePath, $xpath): \DOMNodeList | \DOMNode | string |null
    {
        WsdlAnalyser::loadWsdlXpath($wsdlFilePath, $wsdlId);

        $imports = self::$wsdlDomXpath[$wsdlId]->query(WsdlAnalyser::XPATH_IMPORTS);

        foreach ($imports as $import) {
            $importPath = realpath(dirname($wsdlFilePath)) . DIRECTORY_SEPARATOR . $import->value;
            $wsdlContent = file_get_contents($importPath);

            $importedDomDoc = new \DOMDocument('1.0', 'UTF-8');
            $importedDomDoc->loadXML($wsdlContent);
            $importedDomXpath = new \DOMXPath($importedDomDoc);

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

            $portType = $importedDomXpath->query('//wsdl:definitions/wsdl:portType');
            foreach ($portType as $portType) {
                $node = self::$wsdlDomDoc[$wsdlId]->importNode($portType, true);
                $definitionsNode = self::$wsdlDomDoc[$wsdlId]->getElementsByTagName('definitions')->item(0);
                $definitionsNode->appendChild($node);
            }
        }

        return self::$wsdlDomXpath[$wsdlId]->evaluate($xpath);
    }

    protected static function getRootElement(String $message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $messageName = self::$msgAndVer[$message]['messageName'];
        $rootElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    protected static function getResponseRootElement(String $message)
    {
        $wsdlId = self::$msgAndVer[$message]['wsdl'];
        $messageName = self::$msgAndVer[$message]['outputMessageName'];
        $rootElement = self::evaluateXpathQueryOnWsdl($wsdlId, self::$wsdlIds[$wsdlId], sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    public static function getResponseRootElementNameSpace(String $message)
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

    public static function getNamespace(String $message)
    {
        return self::getResponseRootElementNameSpace($message);
    }

    public static function isStateful(array $params, String $message)
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
                if ($result != false) {
                    return $result;
                }
            }
        }

        return false;
    }

    protected static function getSessionParams(DOMXPath $xml)
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

    public static function sessionWithBody(string $message)
    {
        if ($message != "Hotel_MultiSingleAvailability" && $message != "PNR_Retrieve") {
            return true;
        }
        return false;
    }

    public function HotelSearch($type = 'multi', $params = [])
    {
        $acceptedTypes = ['multi', 'single'];

        if (!in_array($type, $acceptedTypes)) {
            throw new Exception("Type must be either multi or single");
        }

        $defaultparams = [
            "Start" => Carbon::now()->toDateString(),
            "End" => Carbon::now()->addDays(7)->toDateString(),
            "Quantity" => "1",
            "IsPerRoom" => "true",
            "GuestCount" => "1",
            "children" => [],
            "InfoSource" => "Distribution",
            "SearchCacheLevel" => $type == 'multi' ? "LessRecent" : "Live",
            "MaxResponses" => "96",
        ];

        if ($type == 'multi') {
            $defaultparams['SortOrder'] = "RA";
        }

        $HotelRefAttributes = [];

        $sanitizedParams = array_filter($params);

        $params = array_merge($defaultparams, $sanitizedParams);

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

        if (array_key_exists('HotelCityCode', $params) && !array_key_exists('HotelCode', $params)) $HotelRefAttributes['HotelCityCode'] = $params['HotelCityCode'];
        if (array_key_exists('HotelCode', $params)) $HotelRefAttributes['HotelCode'] = $params['HotelCode'];
        if (array_key_exists('ChainCode', $params)) $HotelRefAttributes['ChainCode'] = $params['ChainCode'];

        $GuestCount = [];

        $adults = [
            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $params['GuestCount']],
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
            'InfoSource' => $params['InfoSource'],
        ];

        if (isset($params['MoreDataEchoToken']) && !isset($params['HotelCode'])) {
            $AvailRequestSegmentAttributes['MoreDataEchoToken'] = $params['MoreDataEchoToken'];
        }

        $body = [
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => $AvailRequestSegmentAttributes,
                    'HotelSearchCriteria' => [
                        'Criterion' => [
                            '_attributes' => ['ExactMatch' => 'true'],
                            'HotelRef' => [
                                '_attributes' => $HotelRefAttributes,
                            ],
                        ]
                    ],
                ],
            ],
            'EchoToken' => 'MultiSingle',
            'Version' => '4.000',
            'PrimaryLangID' => 'EN',
            'SummaryOnly' => 'true',
            'AvailRatesOnly' => 'true',
            'RateRangeOnly' => 'true',
            'SearchCacheLevel' => $params['SearchCacheLevel'],
            'RateDetailsInd' => 'true',
            'RequestedCurrency' => $params['Currency'] ?? 'MXN',
            'MaxResponses' => $params['MaxResponses'],
            "ExactMatchOnly" => 'true'

        ];

        if (isset($params['SortOrder'])) {
            $body['SortOrder'] = $params['SortOrder'];
        }

        if ($type == 'multi') {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['_attributes'] = ['AvailableOnlyIndicator' => 'true', 'BestOnlyIndicator' => 'true'];
        }

        if (isset($params['Rating']) && !isset($params['HotelCode'])) {
            if ($params['Rating'] == 5) {
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = [
                    '_attributes' => ['Provider' => 'LSR', 'Rating' => $params['Rating']],
                ];
            } else {
                $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'] = [];

                for ($i = $params['Rating']; $i <= 5; $i++) {
                    $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['Award'][] = [
                        '_attributes' => ['Provider' => 'LSR', 'Rating' => "$i"],
                    ];
                }
            }
        }

        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['StayDateRange'] = [
            '_attributes' => ['Start' => $params['Start'], 'End' => $params['End']],
        ];

        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RatePlanCandidates'] = [
            'RatePlanCandidate' => [
                '_attributes' => ['RatePlanCode' => 'ENF'],
            ],
        ];
        // if (App::environment(['production', 'testing'])) {
        // }

        if ((isset($params['maxRate']) || isset($params['minRate'])) && !isset($params['HotelCode'])) {
            $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RateRange'] = [
                '_attributes' => [
                    'CurrencyCode' => $params['Currency'] ?? 'MXN',
                    'MaxRate' => $params['maxRate'],
                    'MinRate' => isset($params['minRate']) ? $params['minRate'] : "0",
                ],
            ];
        }

        $body['AvailRequestSegments']['AvailRequestSegment']['HotelSearchCriteria']['Criterion']['RoomStayCandidates'] = [
            'RoomStayCandidate' => [
                '_attributes' => ['RoomID' => '1', 'Quantity' => $type == 'multi' ? "1" : $params['Quantity']],
                'GuestCounts' => [
                    '_attributes' => ['IsPerRoom' => "true"],
                    'GuestCount' => $GuestCount,
                ]
            ]
        ];

        return self::Hotel_MultiSingleAvailability($body);
    }

    public function hotelPricing(array $params = [])
    {
        $requiredParams = [
            "Start",
            "End",
            "HotelCode",
            "RatePlanCode",
            "BookingCode",
            "RoomTypeCode",
            "Quantity",
            "IsPerRoom",
            "GuestCount",
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
            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $params['GuestCount']],
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
                                '_attributes' => ['HotelCode' => $params['HotelCode']],
                            ],
                            'StayDateRange' => [
                                '_attributes' => ['Start' => $params['Start'], 'End' => $params['End']],
                            ],
                            'RatePlanCandidates' => [
                                'RatePlanCandidate' => [
                                    '_attributes' => ['RatePlanCode' => $params['RatePlanCode']],
                                ]
                            ],
                            'RoomStayCandidates' => [
                                'RoomStayCandidate' => [
                                    '_attributes' => ['BookingCode' => $params['BookingCode'], 'RoomTypeCode' => $params['RoomTypeCode'], 'RoomID' => '1', 'Quantity' => $params['Quantity']],
                                    'GuestCounts' => [
                                        '_attributes' => ['IsPerRoom' => $params['IsPerRoom']],
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

    protected function isMultiArray($a)
    {
        foreach ($a as $v) if (is_array($v)) return TRUE;
        return FALSE;
    }

    public function addMultiElements($type = "create", $params = [])
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

        $isMultiDimentional = self::isMultiArray($params);

        if ($isMultiDimentional) {
            foreach ($params as $index => $passagener) {
                foreach ($requiredParams as $param) {
                    if (!array_key_exists($param, $passagener)) {
                        throw new Exception("The param $param is required on passenger numer $index");
                    }

                    if (empty($passagener[$param])) {
                        throw new Exception("The param $param cannot be null on passenger numer $index");
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

        $reciveFrom = [
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

            if ($isMultiDimentional) {
                foreach ($params as $key => $value) {
                    array_push($body['travellerInfo'], [
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
                    ]);
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

            array_push($body['dataElementsMaster']['dataElementsIndiv'], [
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
            ]);

            array_push($body['dataElementsMaster']['dataElementsIndiv'], $reciveFrom);

            array_push($body['dataElementsMaster']['dataElementsIndiv'], [
                'elementManagementData' => [
                    'reference' => [
                        'qualifier' => 'OT',
                        'number' => '2'
                    ],
                    'segmentName' => 'TK'
                ],
                'ticketElement' => [
                    'ticket' => [
                        'indicator' => 'OK',
                    ],
                ]
            ]);
        } else {
            $body['dataElementsMaster'] = $dataElementsMaster;
            foreach ($reciveFrom as $key => $value) {
                $body['dataElementsMaster']['dataElementsIndiv'][$key] = $value;
            }
        }

        return self::PNR_AddMultiElements([$body]);
    }

    protected function isMultiArrayWithException($a, $exceptions = [])
    {
        foreach ($a as $k => $v) {
            if (is_array($v) && !array_key_exists($k, array_flip($exceptions))) return true;
        }
        return false;
    }

    public function hotelSell($params = [])
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

        $isMultiDimentional = self::isMultiArrayWithException($params, [
            "passengerReference",
        ]);

        if (!$isMultiDimentional) $requiredParams = array_merge($requiredParams, $roomStayDataParams);

        foreach ($requiredParams as $param) {
            if (!array_key_exists($param, $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[$param])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        if ($isMultiDimentional) {
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
                            $missingPassenegerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReference);
                            if (count($missingPassenegerReferenceParams) > 0) {
                                $missingParamsStrings = implode(", ", array_keys($missingPassenegerReferenceParams));
                                throw new Exception("The params $missingParamsStrings are required on room data number " . ($index + 1));
                            }
                        }
                    } else {
                        $missingPassenegerReferenceParams = array_diff_key(array_flip($passengerReferenceParams, $passengerReferences));
                        if (count($missingPassenegerReferenceParams) > 0) {
                            $missingParamsStrings = implode(", ", array_keys($missingPassenegerReferenceParams));
                            throw new Exception("The params $missingParamsStrings are required on room data number " . ($index + 1));
                        }
                    }
                }
            }
        } else {
            $passengerReferences = $params['passengerReference'];
            if (is_array($passengerReferences)) {
                foreach ($passengerReferences as $passengerReference) {
                    $missingPassenegerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReference);
                    if (count($missingPassenegerReferenceParams) > 0) {
                        $missingParamsStrings = implode(", ", array_keys($missingPassenegerReferenceParams));
                        throw new Exception("The params $missingParamsStrings are required on room data");
                    }
                }
            } else {
                $missingPassenegerReferenceParams = array_diff_key(array_flip($passengerReferenceParams), $passengerReferences);
                if (count($missingPassenegerReferenceParams) > 0) {
                    $missingParamsStrings = implode(", ", array_keys($missingPassenegerReferenceParams));
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


        if (!$isMultiDimentional) {
            $representativeParties = [];
            $guestList = [];

            if (is_array($params['passengerReference'])) {
                foreach ($params['passengerReference'] as $passenger) {

                    array_push($representativeParties, [
                        'occupantList' => [
                            'passengerReference' => [
                                'type' => $passenger['type'],
                                'value' => $passenger['value']
                            ]
                        ]
                    ]);

                    array_push($guestList, [
                        'occupantList' => [
                            'passengerReference' => [
                                'type' => $passenger['type'] == "BHO" ? 'RMO' : 'ROP',
                                'value' => $passenger['value']
                            ]
                        ]
                    ]);
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

                            array_push($representativeParties, [
                                'occupantList' => [
                                    'passengerReference' => [
                                        'type' => $passenger['type'],
                                        'value' => $passenger['value']
                                    ]
                                ]
                            ]);

                            array_push($guestList, [
                                'occupantList' => [
                                    'passengerReference' => [
                                        'type' => $passenger['type'] == "BHO" ? 'RMO' : 'ROP',
                                        'value' => $passenger['value']
                                    ]
                                ]
                            ]);
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

                    array_push($body['roomStayData'], [
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
                    ]);
                }
            }
        }

        return self::Hotel_Sell([$body]);
    }

    public function singOut()
    {
        return self::Security_SignOut();
    }

    public function hotelDescriptiveInfo(array $params = [])
    {
        $requiredParams = ["hotelCode"];

        $defaultparams = [
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

        $params = array_merge($defaultparams, $params);

        if (!is_array($params['hotelCode'])) {
            $HotelDescriptiveInfo = [
                '_attributes' => ['HotelCode' => $params['hotelCode']],
                'HotelInfo' => [
                    '_attributes' => ['SendData' => $params['hotelSendData']]
                ],
                'FacilityInfo' => [
                    '_attributes' => ['SendGuestRooms' => $params['sendGuestRooms'], 'SendMeetingRooms' => $params['sendMeetingRooms'], 'SendRestaurants' =>  $params['sendRestaurants']]
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
                array_push($HotelDescriptiveInfo, [
                    '_attributes' => ['HotelCode' => $hotelCode],
                    'HotelInfo' => [
                        '_attributes' => ['SendData' => $params['hotelSendData']]
                    ],
                    'FacilityInfo' => [
                        '_attributes' => ['SendGuestRooms' => $params['sendGuestRooms'], 'SendMeetingRooms' => $params['sendMeetingRooms'], 'SendRestaurants' =>  $params['sendRestaurants']]
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
                ]);
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

    public function getLastRequest()
    {
        $dom = new \DOMDocument('1.0');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = true;
        $dom->loadXML(self::$client->__getLastRequest());
        return $dom->saveXML();
    }

    public function getLastResponse()
    {
        $dom = new \DOMDocument('1.0');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = true;
        $dom->loadXML(self::$client->__getLastResponse());
        return $dom->saveXML();
    }

    public function pnrRetrieve(array $params = [])
    {

        if (!isset($params['pnrNumber']) || empty($params['pnrNumber'])) {
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

    public function hotelCompleteReservationDetails(array $params = [])
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

    public function pnrCancel(array $params = [])
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
                array_push($cancelElements, [
                    "entryType" => "E",
                    "element" => [
                        "identifier" => "ST",
                        "number" => $segmentNumber
                    ]
                ]);
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

    public function recursiveHotelSearch($type = 'multi', array $params)
    {
        $response =  $this->HotelSearch('multi', $params);
        $hasHotelStays = !empty($response->evaluate("count(//res:Warnings/res:Warning[./@Tag='OK'])"));
        $moreIndicator = $response->evaluate("string(//res:RoomStays/@MoreIndicator)");

        if (!empty($params['MoreDataEchoToken']) && !empty($moreIndicator)) {
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
