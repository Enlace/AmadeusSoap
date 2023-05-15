<?php

namespace Aldogtz\AmadeusSoap\Services;

use DOMDocument;
use DOMXPath;
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use SimpleXMLElement;
use SoapHeader;
use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;
use Throwable;

class AmadeusSoap
{
    protected $client;
    protected $username;
    protected $password;
    protected $officeId;
    protected $msgAndVer = [];
    protected $wsdlDomDoc = [];
    protected $wsdlDomXpath = [];
    protected $wsdlIds = [];
    protected $userIds = [];
    protected $sessions = [];

    public function __construct(String $wsdlPath)
    {
        $this->username = config('amadeus-soap.username');
        $this->password = config('amadeus-soap.password');
        $this->officeId = config('amadeus-soap.officeId');
        $this->client = $this->createClient($wsdlPath);
        $identifier = $this->makeWsdlIdentifier($wsdlPath);
        $this->wsdlIds[$identifier] = $wsdlPath;
        $this->loadWsdlXpath($identifier);
        $this->loadMessagesAndVersions($identifier);
    }

    protected function createClient(String $wsdlPath)
    {
        ini_set("default_socket_timeout", 300);
        return new \SoapClient($wsdlPath, [
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

    public function __call(string $message, array $arguments)
    {
        if (!isset($this->msgAndVer[$message])) {
            throw new Exception("Operation not defined in the wsld");
        }

        $userId = $this->makeWsdlIdentifier(Auth::user()->email);

        $this->client->__setSoapHeaders([]);
        $this->client->__setSoapHeaders($this->createHeaders(Arr::first($arguments) ?? [], $message, $userId));

        $params = $this->createBodyParams(Arr::first($arguments) ?? [], $message);

        try {
            $this->client->{$message}($params);
        } catch (Throwable $e) {

            $request = new DOMDocument('1.0', 'UTF-8');
            $request->formatOutput = true;
            $request->loadXML($this->client->__getLastRequest());
            dd($request->saveXML(), $e);
        }

        if ($message == 'Security_SignOut') {
            session()->forget('amadeusSession');
        }

        $responseObject = simplexml_load_string($this->client->__getLastResponse());
        $responseObject->registerXPathNamespace('res', $this->getResponseRootElementNameSpace($message));
        Http::post('https://webhook.site/d7782234-8acf-4961-9970-e81764c0ab74', [
            "request" => $message,
            "soapBody" => $this->client->__getLastResponse()
        ]);

        $sessionData = $this->getSessionParams($responseObject);
        if (!empty($sessionData)) {
            session(['amadeusSession' => $sessionData]);
        }

        return $responseObject->xpath("//res:{$this->getResponseRootElement($message)}")[0];
    }

    protected function makeWsdlIdentifier(String $wsdlPath)
    {
        return sprintf('%x', crc32($wsdlPath));
    }

    protected function loadWsdlXpath(String $wsdlId)
    {
        $this->wsdlDomDoc[$wsdlId] = new DOMDocument('1.0', 'UTF-8');
        $wsdlContent = file_get_contents($this->wsdlIds[$wsdlId]);
        $this->wsdlDomDoc[$wsdlId]->loadXML($wsdlContent);
        $this->wsdlDomXpath[$wsdlId] = new DOMXPath($this->wsdlDomDoc[$wsdlId]);
        $this->wsdlDomXpath[$wsdlId]->registerNamespace(
            'wsdl',
            'http://schemas.xmlsoap.org/wsdl/'
        );
        $this->wsdlDomXpath[$wsdlId]->registerNamespace(
            'soap',
            'http://schemas.xmlsoap.org/wsdl/soap/'
        );
    }

    protected function loadMessagesAndVersions(String $wsdlId)
    {
        $operations = $this->wsdlDomXpath[$wsdlId]->query('/wsdl:definitions/wsdl:portType/wsdl:operation');

        $msgAndVer = [];

        foreach ($operations as $operation) {

            $inputs = $operation->getElementsByTagName('input');
            $outputs = $operation->getElementsByTagName('output');


            if ($inputs->length > 0) {
                $message = $inputs->item(0)->getAttribute('message');
                $messageName = explode(":", $message)[1];
                $marker = strpos($messageName, '_', strpos($messageName, '_') + 1);
                $num = substr($messageName, $marker + 1);
                $extractedVersion = str_replace('_', '.', $num);

                $outputMessage = $outputs->item(0)->getAttribute('message');
                $outputMessageName = explode(":", $outputMessage)[1];

                $msgAndVer[$operation->getAttribute('name')] = [
                    'version' => $extractedVersion,
                    'wsdl' => $wsdlId,
                    'messageName' => $messageName,
                    'outputMessageName' => $outputMessageName
                ];
            }
        }

        $this->msgAndVer = $msgAndVer;
    }

    protected function createHeaders(array $params = [], String $message, string $userId)
    {
        $headers = [];

        if ($this->isStateful($params, $message)) {
            array_push($headers, $this->createSessionHeader($message, $userId));
        }

        array_push($headers, $this->createMessageIdHeader());
        array_push($headers, $this->createActionHeader($message));
        array_push($headers, $this->createToHeader($message));

        if (!$this->sessionWithBody($message) || !$this->isStateful($params, $message)) {
            array_push($headers, $this->createSecurityHeader());
            array_push($headers, $this->createAMASecurityHostedUserHeader());
        }

        return $headers;
    }

    protected function createSessionHeader(String $message, $userId)
    {
        $body = [];
        $sessionBody = $this->sessionWithBody($message);
        $sessionData = session('amadeusSession');

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

    protected function createMessageIdHeader()
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'MessageID',
            (string) Str::uuid()
        );
    }

    protected function createActionHeader(String $message)
    {
        $wsdlId = $this->msgAndVer[$message]['wsdl'];
        $action = $this->wsdlDomXpath[$wsdlId]->evaluate(sprintf('string(//wsdl:operation[./@name="%s"]/soap:operation/@soapAction)', $message));
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'Action',
            $action
        );
    }

    protected function createToHeader(String $message)
    {
        $wsdlId = $this->msgAndVer[$message]['wsdl'];
        $To = $this->wsdlDomXpath[$wsdlId]->evaluate('string(/wsdl:definitions/wsdl:service/wsdl:port/soap:address/@location)');
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'To',
            $To
        );
    }

    protected function createSecurityHeader()
    {
        $nonce = random_bytes(32);
        $encodedNonce = base64_encode($nonce);
        date_default_timezone_set("UTC");
        $timestamp = Carbon::now()->toIso8601String();
        $passSHA = base64_encode(sha1($nonce . $timestamp . sha1($this->password, true), true));

        return new SoapHeader(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wsswssecurity-secext-1.0.xsd',
            'Security',
            new SoapVar('<oas:Security xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <oas:UsernameToken xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" oas1:Id="UsernameToken-1">
            <oas:Username>' . $this->username . '</oas:Username>
            <oas:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' . $encodedNonce . '</oas:Nonce>
            <oas:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">' . $passSHA . '</oas:Password>
            <oas1:Created>' . $timestamp . '</oas1:Created>
            </oas:UsernameToken>
            </oas:Security>', XSD_ANYXML)
        );
    }

    protected function createAMASecurityHostedUserHeader()
    {
        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Security_v1',
            'AMA_SecurityHostedUser',
            ["UserID" => [
                "_" => "",
                "POS_Type" => "1",
                "PseudoCityCode" => $this->officeId,
                "AgentDutyCode" => "SU",
                "RequestorType" => "U",
            ]]
        );
    }

    protected function createBodyParams(array $params = [], string $message)
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
            'rootElementName' => $this->getRootElement($message),
            '_attributes' => $attributes,
        ]);

        $body = $arrayToXml->dropXmlDeclaration()->prettify()->toXml();

        return new SoapVar($body, XSD_ANYXML);
    }

    protected function getRootElement(String $message)
    {
        $wsdlId = $this->msgAndVer[$message]['wsdl'];
        $messageName = $this->msgAndVer[$message]['messageName'];
        $rootElement = $this->wsdlDomXpath[$wsdlId]->evaluate(sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    protected function getResponseRootElement(String $message)
    {
        $wsdlId = $this->msgAndVer[$message]['wsdl'];
        $messageName = $this->msgAndVer[$message]['outputMessageName'];
        $rootElement = $this->wsdlDomXpath[$wsdlId]->evaluate(sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName));
        return explode(':', $rootElement)[1];
    }

    protected function getResponseRootElementNameSpace(String $message)
    {
        $wsdlId = $this->msgAndVer[$message]['wsdl'];
        $rootElement = $this->wsdlDomXpath[$wsdlId]->evaluate(sprintf("string(//wsdl:operation[@name='%s']/wsdl:output/@message)", $message));
        $nsPrefix = strtolower(explode(':', $rootElement)[1]);
        return $this->wsdlDomXpath[$wsdlId]->query(sprintf("//wsdl:definitions/namespace::%s", $nsPrefix))[0]->namespaceURI;
    }

    public function getNamespace(String $message)
    {
        return $this->getResponseRootElementNameSpace($message);
    }

    protected function isStateful(array $params, String $message)
    {
        if ($message == "Hotel_DescriptiveInfo" || $message == "PNR_Retrieve") {
            return false;
        }

        if ($message == "Hotel_MultiSingleAvailability") {
            if ($this->multiKeyExists($params, 'HotelCityCode') != false) {
                return false;
            }
        }

        return true;
    }

    protected function multiKeyExists(array $arr, $key)
    {

        // is in base array?
        if (array_key_exists($key, $arr)) {
            return $arr[$key];
        }

        // check arrays contained in this array
        foreach ($arr as $element) {
            if (is_array($element)) {
                $result = $this->multiKeyExists($element, $key);
                if ($result != false) {
                    return $result;
                }
            }
        }

        return false;
    }

    protected function getSessionParams(SimpleXMLElement $xml)
    {
        if ((string)$xml->xpath('//awsse:Session/@TransactionStatusCode')[0] != "InSeries") {
            return [];
        }

        $sessionId = (string)$xml->xpath('//awsse:Session/awsse:SessionId')[0];
        $sequenceNumber = (string)$xml->xpath('//awsse:Session/awsse:SequenceNumber')[0];
        $securityToken = (string)$xml->xpath('//awsse:Session/awsse:SecurityToken')[0];

        return [
            "sessionId" => $sessionId,
            "sequenceNumber" => $sequenceNumber,
            "securityToken" => $securityToken,
        ];
    }

    protected function sessionWithBody(string $message)
    {
        if ($message != "Hotel_MultiSingleAvailability" && $message != "PNR_Retrieve") {
            return true;
        }
        return false;
    }

    protected function saveSessionData(array $data, string $userId)
    {
        $this->sessions[$userId] = $data;
    }

    public function HotelSearch($type = "city", $params = [])
    {
        $acceptedTypes = ['city', 'rating', 'hotel', 'chain'];
        $defaultparams = [
            "Start" => Carbon::now()->toDateString(),
            "End" => Carbon::now()->addDays(7)->toDateString(),
            "order" => "RA",
            "Quantity" => "1",
            "IsPerRoom" => "true",
            "GuestCount" => "1"
        ];

        $HotelRefAttributes = [];
        $Award = null;

        if (!in_array($type, $acceptedTypes)) {
            throw new Exception("Hotel Search Type Not Supported");
        }

        if ($type == 'rating') {
            $defaultparams["Rating"] = "3";
        }

        if ($type == 'hotel') {
            $defaultparams["HotelCode"] = null;
        }

        if ($type == 'chain') {
            $defaultparams["ChainCode"] = null;
        }

        $sanitizedParams = array_filter($params);

        $params = array_merge($defaultparams, $sanitizedParams);

        foreach ($params as $key => $value) {
            if ($value == null) {
                throw new Exception("$key cannot be null");
            }
        }

        if (array_key_exists('HotelCityCode', $params) && !array_key_exists('HotelCode', $params)) $HotelRefAttributes['HotelCityCode'] = $params['HotelCityCode'];
        if (array_key_exists('HotelCode', $params)) $HotelRefAttributes['HotelCode'] = $params['HotelCode'];
        if (array_key_exists('ChainCode', $params)) $HotelRefAttributes['ChainCode'] = $params['ChainCode'];
        if (array_key_exists('Rating', $params)) {
            $Award = [
                '_attributes' => ['Provider' => 'LSR', 'Rating' => $params['Rating']],
            ];
        };


        return $this->Hotel_MultiSingleAvailability([
            'AvailRequestSegments' => [
                'AvailRequestSegment' => [
                    '_attributes' => ['InfoSource' => 'Distribution'],
                    'HotelSearchCriteria' => [
                        'Criterion' => [
                            '_attributes' => ['ExactMatch' => 'true'],
                            'HotelRef' => [
                                '_attributes' => $HotelRefAttributes,
                            ],
                            'Award' => $Award,
                            'StayDateRange' => [
                                '_attributes' => ['Start' => $params['Start'], 'End' => $params['End']],
                            ],
                            'RoomStayCandidates' => [
                                'RoomStayCandidate' => [
                                    '_attributes' => ['RoomID' => '1', 'Quantity' => $params['Quantity']],
                                    'GuestCounts' => [
                                        '_attributes' => ['IsPerRoom' => $params['IsPerRoom']],
                                        'GuestCount' => [
                                            '_attributes' => ['AgeQualifyingCode' => '10', 'Count' => $params['GuestCount']],
                                        ]
                                    ]
                                ]
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
            'SearchCacheLevel' => 'Live',
            'RateDetailsInd' => 'true',
            'RequestedCurrency' => 'MXN',
        ]);
    }

    public function hotelPricing(array $params = [])
    {
        $requiredParams = [
            "Start",
            "End",
            "HotelCode",
            "RatePlanCode",
            "BookingCode",
            "Quantity",
            "RoomTypeCode",
            "IsPerRoom",
            "AgeQualifyingCode",
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

        return $this->Hotel_EnhancedPricing([
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
                            'RoomStayCandidates' => [
                                'RoomStayCandidate' => [
                                    '_attributes' => ['BookingCode' => $params['BookingCode'], 'RoomTypeCode' => $params['RoomTypeCode'], 'RoomID' => '1', 'Quantity' => $params['Quantity']],
                                    'GuestCounts' => [
                                        '_attributes' => ['IsPerRoom' => $params['IsPerRoom']],
                                        'GuestCount' => [
                                            '_attributes' => ['AgeQualifyingCode' => $params['AgeQualifyingCode'], 'Count' => $params['GuestCount']],
                                        ]
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

    public function addMultiElements($type = "create", $params = [])
    {
        $acceptedTypes = ['create', 'end'];
        $requiredParams = $type == 'end' ? [] : [
            "firstName",
            "surname",
        ];


        $body = [];

        if (!in_array($type, $acceptedTypes)) {
            throw new Exception("Hotel Search Type Not Supported");
        }

        foreach ($requiredParams as $param) {
            if (!array_key_exists($param, $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[$param])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        $body['pnrActions'] = [
            'optionCode' => $type == 'create' ? '0' : '11'
        ];

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
                'longFreetext' => $type == 'create' ? 'Added via WebService' : 'hotel reservation via WebServices'
            ]
        ];

        if ($type == 'create') {
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
                            'firstName' => $params['firstName'],
                            'type' => 'ADT'
                        ]
                    ]
                ]
            ];

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

            array_push($body['dataElementsMaster']['dataElementsIndiv'], $reciveFrom);
        } else {
            $body['dataElementsMaster'] = $dataElementsMaster;
            foreach ($reciveFrom as $key => $value) {
                $body['dataElementsMaster']['dataElementsIndiv'][$key] = $value;
            }
        }

        return $this->PNR_AddMultiElements([$body]);
    }

    public function hotelSell($params = [])
    {
        $requiredParams = [
            "chainCode",
            "cityCode",
            "hotelCode",
            "passengerReference",
            "paymentType",
            "bookingCode",
            "firstName",
            "surname",
            "vendorCode",
            "cardNumber",
            "securityId",
            "expiryDate",
            "travelAgentRef"
        ];

        foreach ($requiredParams as $param) {
            if (!array_key_exists($param, $params)) {
                throw new Exception("The param $param is required");
            }

            if (empty($params[$param])) {
                throw new Exception("The param $param cannot be null");
            }
        }

        return $this->Hotel_Sell([
            [
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
                'roomStayData' => [
                    'markerRoomStayData' => null,
                    'globalBookingInfo' => [
                        'markerGlobalBookingInfo' => [
                            'hotelReference' => [
                                'chainCode' => (string)$params['chainCode'],
                                'cityCode' => (string)$params['cityCode'],
                                'hotelCode' => substr((string)$params['hotelCode'], -3)
                            ],

                        ],
                        'representativeParties' => [
                            'occupantList' => [
                                'passengerReference' => [
                                    'type' => 'BHO',
                                    'value' => $params['passengerReference']
                                ]
                            ]
                        ]
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
                        'guestList' => [
                            'occupantList' => [
                                'passengerReference' => [
                                    'type' => 'RMO',
                                    'value' => $params['passengerReference']
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]);
    }

    public function singOut()
    {
        return $this->Security_SignOut();
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

        return $this->Hotel_DescriptiveInfo([
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
        return $this->client->__getLastRequest();
    }
}
