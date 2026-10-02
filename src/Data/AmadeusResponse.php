<?php

namespace Aldogtz\AmadeusSoap\Data;

use Aldogtz\AmadeusSoap\Exceptions\XmlParseException;
use Aldogtz\AmadeusSoap\Session\SessionData;
use DOMDocument;
use DOMNode;
use DOMNodeList;
use DOMXPath;

class AmadeusResponse
{
    protected DOMXPath $xpath;

    protected DOMDocument $document;

    /**
     * @throws XmlParseException If the XML cannot be parsed.
     */
    public function __construct(
        protected string $xml,
        protected string $responseNamespace,
    ) {
        if (trim($xml) === '') {
            throw XmlParseException::emptyResponse();
        }

        $this->document = new DOMDocument('1.0', 'UTF-8');

        // Use internal error handling to capture libxml errors
        // instead of emitting PHP warnings.
        $previousUseErrors = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $loaded = $this->document->loadXML($this->xml);

        $xmlErrors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previousUseErrors);

        if (! $loaded || ! empty($xmlErrors)) {
            // Filter: only fatal/error level errors fail parsing.
            // Warnings (level 1) are tolerated.
            $fatalErrors = array_filter(
                $xmlErrors,
                fn (\LibXMLError $e) => $e->level >= LIBXML_ERR_ERROR,
            );

            if (! $loaded || ! empty($fatalErrors)) {
                throw XmlParseException::fromLibxmlErrors(
                    ! empty($fatalErrors) ? $fatalErrors : $xmlErrors,
                    $this->xml,
                );
            }
        }

        $this->xpath = new DOMXPath($this->document);
        $this->xpath->registerNamespace('res', $this->responseNamespace);
        $this->xpath->registerNamespace('awsse', 'http://xml.amadeus.com/2010/06/Session_v3');
    }

    /**
     * Wrap reply XML without knowing its namespace: it is read from the
     * reply element (the first child of the SOAP Body, or the root element
     * of a bare reply).
     *
     * @throws XmlParseException If the XML cannot be parsed.
     */
    public static function fromXml(string $xml): self
    {
        if (trim($xml) === '') {
            throw XmlParseException::emptyResponse();
        }

        $document = new DOMDocument;
        $previousUseErrors = libxml_use_internal_errors(true);
        $loaded = $document->loadXML($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($previousUseErrors);

        $namespace = '';
        if ($loaded && $document->documentElement !== null) {
            $reply = $document->documentElement;
            $body = $document->getElementsByTagNameNS('http://schemas.xmlsoap.org/soap/envelope/', 'Body')->item(0);

            foreach ($body?->childNodes ?? [] as $node) {
                if ($node instanceof \DOMElement) {
                    $reply = $node;
                    break;
                }
            }

            $namespace = (string) $reply->namespaceURI;
        }

        // A document that failed to load is rejected by the constructor
        return new self($xml, $namespace);
    }

    /**
     * Evaluate an XPath expression (backward-compatible with DOMXPath::evaluate).
     */
    public function evaluate(string $expression, ?DOMNode $contextNode = null): mixed
    {
        if ($contextNode !== null) {
            return $this->xpath->evaluate($expression, $contextNode);
        }

        return $this->xpath->evaluate($expression);
    }

    /**
     * Query the DOM using XPath.
     */
    public function query(string $expression, ?DOMNode $contextNode = null): DOMNodeList|false
    {
        if ($contextNode !== null) {
            return $this->xpath->query($expression, $contextNode);
        }

        return $this->xpath->query($expression);
    }

    public function hasErrors(): bool
    {
        $errors = $this->evaluate('//res:Errors/res:Error');

        return $errors instanceof DOMNodeList && $errors->length > 0;
    }

    public function getErrors(): array
    {
        $errors = [];
        $errorNodes = $this->evaluate('//res:Errors/res:Error');

        if ($errorNodes instanceof DOMNodeList) {
            foreach ($errorNodes as $node) {
                $errors[] = $node->textContent;
            }
        }

        return $errors;
    }

    public function hasOkWarning(): bool
    {
        return ! empty($this->evaluate("count(//res:Warnings/res:Warning[./@Tag = 'OK'])"));
    }

    /**
     * Check if the response indicates a session-level error (expired/invalid).
     */
    public function hasSessionError(): bool
    {
        // Check SOAP header for session errors
        $sessionStatus = (string) $this->evaluate('string(//awsse:Session/@TransactionStatusCode)');

        if ($sessionStatus === 'End') {
            // Session ended unexpectedly — may indicate server-side timeout
            return false; // End is normal for sign-out
        }

        // Check error nodes for session-related error codes
        $errorNodes = $this->evaluate('//res:Errors/res:Error');

        if ($errorNodes instanceof DOMNodeList) {
            foreach ($errorNodes as $node) {
                $code = (string) $this->evaluate('string(./@Code)', $node);
                $text = strtolower($node->textContent);

                if (str_contains($code, 'Session') || str_contains($text, 'session')) {
                    return true;
                }
            }
        }

        return false;
    }

    public function getSessionData(): ?SessionData
    {
        return SessionData::fromResponse($this->xpath);
    }

    public function getRawXml(): string
    {
        return $this->xml;
    }

    public function xpath(): DOMXPath
    {
        return $this->xpath;
    }

    public function document(): DOMDocument
    {
        return $this->document;
    }

    public function getResponseNamespace(): string
    {
        return $this->responseNamespace;
    }
}
