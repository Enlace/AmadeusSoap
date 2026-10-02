<?php

namespace Aldogtz\AmadeusSoap\Exceptions;

/**
 * Thrown when required parameters are missing or invalid
 * in a Params class's fromArray() method.
 */
class InvalidParameterException extends AmadeusSoapException
{
    /** @var array<string, string> */
    protected array $validationErrors = [];

    /**
     * Create an exception for missing required fields.
     *
     * @param  string  $paramsClass  Short name (e.g. 'HotelSearchParams')
     * @param  array<string, string>  $errors  Field name => error message
     */
    public static function forValidation(string $paramsClass, array $errors): self
    {
        $messages = array_map(
            fn (string $field, string $message) => "{$field}: {$message}",
            array_keys($errors),
            array_values($errors),
        );

        $exception = new self(
            "Invalid parameters for {$paramsClass}: " . implode('; ', $messages)
        );

        $exception->validationErrors = $errors;

        return $exception;
    }

    /**
     * Get the validation errors keyed by field name.
     *
     * @return array<string, string>
     */
    public function getValidationErrors(): array
    {
        return $this->validationErrors;
    }
}
