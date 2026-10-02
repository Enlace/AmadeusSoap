<?php

namespace Aldogtz\AmadeusSoap\Data\Concerns;

use Aldogtz\AmadeusSoap\Exceptions\InvalidParameterException;

/**
 * Shared validation helpers for Params classes.
 */
trait ValidatesParams
{
    /**
     * Validate that required fields are present and non-empty in the data array.
     *
     * @param  array<string, mixed>  $data      The input data to validate.
     * @param  array<string>         $required  List of required field names.
     * @param  string                $class     Short class name for the error message.
     *
     * @throws InvalidParameterException
     */
    protected static function validateRequired(array $data, array $required, string $class): void
    {
        $errors = [];

        foreach ($required as $field) {
            if (! array_key_exists($field, $data) || (is_string($data[$field]) && trim($data[$field]) === '')) {
                $errors[$field] = 'is required';
            }
        }

        if (! empty($errors)) {
            throw InvalidParameterException::forValidation($class, $errors);
        }
    }

    /**
     * Validate a date string is a valid Y-m-d format.
     *
     * @param  array<string, mixed>  $data   The input data.
     * @param  array<string>         $fields Date field names to validate.
     * @param  string                $class  Short class name for the error message.
     *
     * @throws InvalidParameterException
     */
    protected static function validateDates(array $data, array $fields, string $class): void
    {
        $errors = [];

        foreach ($fields as $field) {
            if (! isset($data[$field]) || ! is_string($data[$field])) {
                continue; // Skip missing — handled by validateRequired
            }

            $value = $data[$field];

            if (! preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
                $errors[$field] = "must be a valid date (YYYY-MM-DD), got '{$value}'";
            }
        }

        if (! empty($errors)) {
            throw InvalidParameterException::forValidation($class, $errors);
        }
    }

    /**
     * Resolve a backed-enum field that may be given as a case or as its value.
     *
     * @template T of \BackedEnum
     *
     * @param  array<string, mixed>  $data     The input data.
     * @param  string                $field    Field name to resolve.
     * @param  class-string<T>       $enum     Backed enum class.
     * @param  T                     $default  Used when the field is missing or null.
     * @param  string                $class    Short class name for the error message.
     * @return T
     *
     * @throws InvalidParameterException
     */
    protected static function resolveEnum(array $data, string $field, string $enum, \BackedEnum $default, string $class): \BackedEnum
    {
        $value = $data[$field] ?? $default;

        if ($value instanceof $enum) {
            return $value;
        }

        $case = is_string($value) || is_int($value) ? $enum::tryFrom($value) : null;

        if ($case === null) {
            $allowed = implode(', ', array_map(fn (\BackedEnum $case) => $case->value, $enum::cases()));
            $given = is_scalar($value) ? "'{$value}'" : get_debug_type($value);

            throw InvalidParameterException::forValidation($class, [
                $field => "must be one of: {$allowed}, got {$given}",
            ]);
        }

        return $case;
    }
}
