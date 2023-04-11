<?php

namespace Aldogtz\AmadeusSoap\Services;

use DOMDocument;
use DOMXPath;
use Exception;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SoapClient;
use SoapHeader;
use SoapVar;

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
        return new SoapClient($wsdlPath, [
            'trace' => true,
            'exception' => true,
        ]);
    }

    protected function __call($message, $arguments)
    {
        if (!isset($this->msgAndVer[$message])) {
            throw new Exception("Operation not defined in the wsld");
        }

        $this->client->__setSoapHeaders($this->createHeaders($message));

        // $this->client->{$message}($params);

        dd(["método" => $message, "argumentos" => $arguments]);
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

            if ($inputs->length > 0) {
                $message = $inputs->item(0)->getAttribute('message');
                $messageName = explode(":", $message)[1];
                $marker = strpos($messageName, '_', strpos($messageName, '_') + 1);
                $num = substr($messageName, $marker + 1);
                $extractedVersion = str_replace('_', '.', $num);

                $msgAndVer[$operation->getAttribute('name')] = [
                    'version' => $extractedVersion,
                    'wsdl' => $wsdlId
                ];
            }
        }
        $this->msgAndVer = $msgAndVer;
    }

    protected function createHeaders(String $message)
    {
        $headers = [];

        array_push($headers, $this->createMessageIdHeader());
        array_push($headers, $this->createActionHeader($message));
        array_push($headers, $this->createToHeader($message));
        array_push($headers, $this->createSecurityHeader());
        array_push($headers, $this->createAMASecurityHostedUserHeader());

        return $headers;
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

    protected function createBody()
    {
    }
}
