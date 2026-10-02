<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

use LibXMLError;

/**
 * Thrown when the response XML from Amadeus is malformed or cannot be parsed.
 */
class XmlParseException extends AmadeusSoapException
{
    /** @var LibXMLError[] */
    protected array $xmlErrors = [];

    protected ?string $rawXml = null;

    /**
     * Create from libxml errors.
     *
     * @param  LibXMLError[]  $errors
     */
    public static function fromLibxmlErrors(array $errors, ?string $rawXml = null): self
    {
        $messages = array_map(
            fn (LibXMLError $error) => trim($error->message) . " (line {$error->line}, column {$error->column})",
            $errors,
        );

        $exception = new self(
            'Failed to parse Amadeus XML response: ' . implode('; ', $messages)
        );

        $exception->xmlErrors = $errors;
        $exception->rawXml = $rawXml;

        return $exception;
    }

    /**
     * Create from a generic parse failure.
     */
    public static function emptyResponse(): self
    {
        return new self('Amadeus returned an empty response.');
    }

    /**
     * Get the libxml errors.
     *
     * @return LibXMLError[]
     */
    public function getXmlErrors(): array
    {
        return $this->xmlErrors;
    }

    /**
     * Get the raw XML that failed to parse.
     */
    public function getRawXml(): ?string
    {
        return $this->rawXml;
    }
}
