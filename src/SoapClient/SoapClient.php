<?php

namespace Aldogtz\AmadeusSoap\SoapClient;

use Aldogtz\AmadeusSoap\Services\AmadeusSoap;
use Aldogtz\AmadeusSoap\WsdlAnalyser\InvalidWsdlFileException;
use Aldogtz\AmadeusSoap\WsdlAnalyser\WsdlAnalyser;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SoapHeader;
use SoapVar;
use Spatie\ArrayToXml\ArrayToXml;

class SoapClient extends \SoapClient
{
    private $username;
    private $password;
    private $wsdlDomXpath;
    private $wsdlDomDoc;
    private $options;

    public function __construct($wsdl, array $options = [])
    {
        $this->options = $options;
        $this->loadWsdlXpath($wsdl);
        $operations = $this->wsdlDomXpath->query(WsdlAnalyser::XPATH_ALL_OPERATIONS);
        if ($operations->length === 0) {
            $imports = $this->wsdlDomXpath->query(WsdlAnalyser::XPATH_IMPORTS);
            foreach ($imports as $import) {
                $importPath = realpath(dirname($wsdl)) . DIRECTORY_SEPARATOR . $import->value;
                $wsdlContent = file_get_contents($importPath);
                $importedDomDoc = new \DOMDocument('1.0', 'UTF-8');
                $importedDomDoc->loadXML($wsdlContent);
                $node = $this->wsdlDomDoc->importNode($importedDomDoc->childNodes->item(0), true);
                $this->wsdlDomDoc->documentElement->appendChild($node);
            }
        }
        parent::__construct($wsdl, $options);
    }

    public function __setUsernameToken($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }

    private function generateWSSecurityHeader()
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

    private function generateMessageIdHeader()
    {
        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'MessageID',
            (string) Str::uuid()
        );
    }

    private function createToHeader()
    {
        $To = $this->wsdlDomXpath->evaluate('string(/wsdl:definitions/wsdl:service/wsdl:port/soap:address/@location)');

        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'To',
            $To
        );
    }

    private function createActionHeader(String $message)
    {
        $action = $this->wsdlDomXpath->evaluate(sprintf('string(//wsdl:operation[./@name="%s"]/soap:operation/@soapAction)', $message));

        return new SoapHeader(
            'http://www.w3.org/2005/08/addressing',
            'Action',
            $action
        );
    }

    protected function createSessionHeader(String $message)
    {
        $body = [];
        $sessionBody = AmadeusSoap::sessionWithBody($message);
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

    protected function createAMASecurityHostedUserHeader()
    {
        return new SoapHeader(
            'http://xml.amadeus.com/2010/06/Security_v1',
            'AMA_SecurityHostedUser',
            ["UserID" => [
                "_" => "",
                "POS_Type" => "1",
                "PseudoCityCode" => AmadeusSoap::$officeId,
                "AgentDutyCode" => "SU",
                "RequestorType" => "U",
            ]]
        );
    }

    protected function createHeaders(array $params = [], String $message)
    {
        $headers = [];

        if (AmadeusSoap::isStateful($params, $message)) {
            array_push($headers, $this->createSessionHeader($message));
        }

        array_push($headers, $this->generateMessageIdHeader());
        array_push($headers, $this->createActionHeader($message));
        array_push($headers, $this->createToHeader($message));

        if (!AmadeusSoap::sessionWithBody($message) || !AmadeusSoap::isStateful($params, $message)) {
            array_push($headers, $this->generateWSSecurityHeader());
            array_push($headers, $this->createAMASecurityHostedUserHeader());
        }

        return $headers;
    }

    // public function __soapCall($function_name, $arguments, $options = null, $input_headers = null, &$output_headers = null)
    // {
    //     dd($function_name, $arguments, $options, $input_headers, $output_headers);
    //     return parent::__soapCall($function_name, $arguments, $options, $this->generateWSSecurityHeader());
    // }

    function __call($function_name, $arguments)
    {
        $headers = $this->createHeaders($arguments, $function_name);
        return parent::__soapCall($function_name, $arguments, $this->options, $headers);
    }

    private function loadWsdlXpath($wsdlFilePath)
    {
        if (!isset($this->wsdlDomXpath) || is_null($this->wsdlDomXpath)) {
            $wsdlContent = file_get_contents($wsdlFilePath);

            if ($wsdlContent !== false) {
                $this->wsdlDomDoc = new \DOMDocument('1.0', 'UTF-8');
                $this->wsdlDomDoc->loadXML($wsdlContent);
                $this->wsdlDomXpath = new \DOMXPath($this->wsdlDomDoc);
                $this->wsdlDomXpath->registerNamespace(
                    'wsdl',
                    'http://schemas.xmlsoap.org/wsdl/'
                );
                $this->wsdlDomXpath->registerNamespace(
                    'soap',
                    'http://schemas.xmlsoap.org/wsdl/soap/'
                );
            } else {
                throw new InvalidWsdlFileException('WSDL ' . $wsdlFilePath . ' could not be loaded');
            }
        }
    }
}
