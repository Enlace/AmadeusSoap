<?php

namespace Aldogtz\AmadeusSoap\Wsdl;

use Aldogtz\AmadeusSoap\Wsdl\Exceptions\InvalidWsdlFileException;
use DOMDocument;
use DOMXPath;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;

class WsdlManager
{
    const XPATH_ALL_OPERATIONS = '/wsdl:definitions/wsdl:portType/wsdl:operation/@name';

    const XPATH_IMPORTS = '/wsdl:definitions/wsdl:import/@location';

    const XPATH_VERSION_FOR_OPERATION = "string(/wsdl:definitions/wsdl:message[contains(./@name, '%s_')]/@name)";

    const XPATH_ALT_VERSION_FOR_OPERATION = "string(//wsdl:operation[contains(./@name, '%s')]/wsdl:input/@message)";

    /** @var array<string, string> wsdlId => path */
    protected array $wsdlIds = [];

    /** @var array<string, DOMDocument> */
    protected array $wsdlDomDoc = [];

    /** @var array<string, DOMXPath> */
    protected array $wsdlDomXpath = [];

    protected ?OperationRegistry $registry = null;

    protected bool $loaded = false;

    /** @var array<string, true> wsdlIds whose imports have been merged into the base DOM */
    protected array $importsMerged = [];

    public function __construct(protected string $wsdlPath) {}

    /**
     * Get the operation registry, loading WSDLs on first access.
     *
     * Lazy-loading avoids parsing all WSDL files (~20-50ms) at service
     * provider boot time. The registry is built once and cached for the
     * entire request lifecycle.
     */
    public function getRegistry(): OperationRegistry
    {
        $this->ensureLoaded();

        return $this->registry;
    }

    public function getWsdlIds(): array
    {
        $this->ensureLoaded();

        return $this->wsdlIds;
    }

    public function getWsdlDomXpath(): array
    {
        $this->ensureLoaded();

        return $this->wsdlDomXpath;
    }

    public function getWsdlDomDoc(): array
    {
        $this->ensureLoaded();

        return $this->wsdlDomDoc;
    }

    /**
     * Load WSDLs on first access, not at construction time.
     */
    protected function ensureLoaded(): void
    {
        if ($this->loaded) {
            return;
        }

        $this->registry = new OperationRegistry;
        $this->loadAllWsdls();
        $this->loaded = true;

        // Free DOM objects after extracting metadata — they're only
        // needed during parsing and consume ~200KB+ of memory per WSDL.
        $this->wsdlDomDoc = [];
        $this->wsdlDomXpath = [];
    }

    protected function loadAllWsdls(): void
    {
        if (! is_dir($this->wsdlPath)) {
            throw new InvalidWsdlFileException(
                "WSDL path '{$this->wsdlPath}' is not a readable directory. Check the amadeus-soap.wsdl_path config value."
            );
        }

        $files = scandir($this->wsdlPath);

        $wsdls = Arr::where($files, fn ($path) => Str::endsWith($path, '.wsdl'));

        $wsdlPaths = Arr::map($wsdls, fn ($path) => $this->wsdlPath.DIRECTORY_SEPARATOR.$path);

        foreach ($wsdlPaths as $wsdlFilePath) {
            $wsdlId = $this->makeWsdlIdentifier($wsdlFilePath);
            $this->wsdlIds[$wsdlId] = $wsdlFilePath;
            $this->loadWsdlXpath($wsdlFilePath, $wsdlId);

            $operations = $this->wsdlDomXpath[$wsdlId]->query(self::XPATH_ALL_OPERATIONS);

            if ($operations->length === 0) {
                $imports = $this->wsdlDomXpath[$wsdlId]->query(self::XPATH_IMPORTS);

                foreach ($imports as $import) {
                    if (! empty($import->value)) {
                        $this->loadMessagesFromImportedWsdl($import->value, $wsdlFilePath, $wsdlId);
                    }
                }
            }

            $this->extractOperations($operations, self::XPATH_VERSION_FOR_OPERATION, $wsdlId, $this->wsdlDomXpath[$wsdlId], $wsdlFilePath);
        }
    }

    protected function loadMessagesFromImportedWsdl(string $import, string $wsdlPath, string $wsdlId): void
    {
        $importPath = realpath(dirname($wsdlPath)).DIRECTORY_SEPARATOR.$import;
        $wsdlContent = file_get_contents($importPath);

        if ($wsdlContent === false) {
            throw new InvalidWsdlFileException("WSDL {$importPath} import could not be loaded");
        }

        $domDoc = new DOMDocument('1.0', 'UTF-8');
        $domDoc->loadXML($wsdlContent);
        $domXpath = new DOMXPath($domDoc);
        $domXpath->registerNamespace('wsdl', 'http://schemas.xmlsoap.org/wsdl/');
        $domXpath->registerNamespace('soap', 'http://schemas.xmlsoap.org/wsdl/soap/');

        $nodeList = $domXpath->query(self::XPATH_ALL_OPERATIONS);

        $this->extractOperations(
            $nodeList,
            self::XPATH_ALT_VERSION_FOR_OPERATION,
            $wsdlId,
            $domXpath,
            $wsdlPath
        );
    }

    protected function extractOperations(
        \DOMNodeList $operations,
        string $query,
        string $wsdlId,
        DOMXPath $domXpath,
        string $wsdlPath
    ): void {
        foreach ($operations as $operation) {
            if (empty($operation->value)) {
                continue;
            }

            $operationName = $operation->value;
            $fullVersion = $domXpath->evaluate(sprintf($query, $operationName));

            if (empty($fullVersion)) {
                continue;
            }

            $version = $this->extractMessageVersion($fullVersion);

            $inputMsgRef = $domXpath->evaluate(sprintf(
                "string(//wsdl:operation[./@name = '%s']/wsdl:input/@message)",
                $operationName
            ));
            $inputMessageName = str_contains($inputMsgRef, ':')
                ? explode(':', $inputMsgRef)[1]
                : $inputMsgRef;

            $outputMsgRef = $domXpath->evaluate(sprintf(
                "string(//wsdl:operation[./@name = '%s']/wsdl:output/@message)",
                $operationName
            ));
            $outputMessageName = str_contains($outputMsgRef, ':')
                ? explode(':', $outputMsgRef)[1]
                : $outputMsgRef;

            $this->registry->register($operationName, new OperationMetadata(
                name: $operationName,
                wsdlId: $wsdlId,
                wsdlPath: $this->wsdlIds[$wsdlId],
                version: $version,
                inputMessageName: $inputMessageName,
                outputMessageName: $outputMessageName,
                soapAction: $this->resolveSoapAction($operationName, $wsdlId),
                serviceEndpoint: $this->resolveEndpoint($wsdlId),
                rootElement: $this->resolveRootElement($operationName, $wsdlId),
                responseRootElement: $this->resolveResponseRootElement($operationName, $wsdlId),
                responseNamespace: $this->resolveResponseNamespace($operationName, $wsdlId),
            ));
        }
    }

    protected function resolveSoapAction(string $operation, string $wsdlId): string
    {
        $action = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf('string(//wsdl:operation[./@name="%s"]/soap:operation/@soapAction)', $operation)
        );

        return $action ?: '';
    }

    protected function resolveEndpoint(string $wsdlId): string
    {
        return $this->evaluateOnWsdl(
            $wsdlId,
            'string(/wsdl:definitions/wsdl:service/wsdl:port/soap:address/@location)'
        ) ?: '';
    }

    protected function resolveRootElement(string $operation, string $wsdlId): string
    {
        $this->ensureImportsMerged($wsdlId);

        $inputMsgRef = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:portType/wsdl:operation[@name='%s']/wsdl:input/@message)", $operation)
        );

        $messageName = str_contains($inputMsgRef, ':')
            ? explode(':', $inputMsgRef)[1]
            : $inputMsgRef;

        $element = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName)
        );

        return str_contains($element, ':') ? explode(':', $element)[1] : $element;
    }

    protected function resolveResponseRootElement(string $operation, string $wsdlId): string
    {
        $this->ensureImportsMerged($wsdlId);

        $outputMsgRef = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:portType/wsdl:operation[@name='%s']/wsdl:output/@message)", $operation)
        );

        $messageName = str_contains($outputMsgRef, ':')
            ? explode(':', $outputMsgRef)[1]
            : $outputMsgRef;

        $element = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:message[contains(./@name, '%s')]/wsdl:part/@element)", $messageName)
        );

        return str_contains($element, ':') ? explode(':', $element)[1] : $element;
    }

    public function resolveResponseNamespace(string $operation, string $wsdlId): string
    {
        $this->ensureImportsMerged($wsdlId);

        $outputMsgRef = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:portType/wsdl:operation[@name='%s']/wsdl:output/@message)", $operation)
        );

        $messageName = str_contains($outputMsgRef, ':')
            ? explode(':', $outputMsgRef)[1]
            : $outputMsgRef;

        $messageElement = $this->evaluateOnWsdl(
            $wsdlId,
            sprintf("string(//wsdl:definitions/wsdl:message[./@name = '%s']/wsdl:part/@element)", $messageName)
        );

        $nsPrefix = str_contains($messageElement, ':')
            ? explode(':', $messageElement)[0]
            : '';

        if (empty($nsPrefix)) {
            return '';
        }

        $namespaces = $this->evaluateOnWsdl($wsdlId, '//wsdl:definitions/namespace::*');

        foreach ($namespaces as $namespace) {
            if ($namespace->prefix === $nsPrefix) {
                return $namespace->namespaceURI;
            }
        }

        return '';
    }

    /** Merge imports into the base WSDL DOM so all messages/portTypes are queryable */
    protected function ensureImportsMerged(string $wsdlId): void
    {
        // Tracked per instance, not statically: wsdlIds are a hash of the file
        // path, so a static cache would make every WsdlManager built after the
        // first one in the same process skip the merge and resolve empty
        // rootElement/responseNamespace for imported operations.
        if (isset($this->importsMerged[$wsdlId])) {
            return;
        }
        $this->importsMerged[$wsdlId] = true;

        $wsdlFilePath = $this->wsdlIds[$wsdlId];
        $imports = $this->wsdlDomXpath[$wsdlId]->query(self::XPATH_IMPORTS);

        foreach ($imports as $import) {
            $importPath = realpath(dirname($wsdlFilePath)).DIRECTORY_SEPARATOR.$import->value;
            $wsdlContent = file_get_contents($importPath);

            if ($wsdlContent === false) {
                continue;
            }

            $importedDomDoc = new DOMDocument('1.0', 'UTF-8');
            $importedDomDoc->loadXML($wsdlContent);
            $importedDomXpath = new DOMXPath($importedDomDoc);

            // Merge missing namespaces
            $importedNamespaces = $importedDomXpath->evaluate('//wsdl:definitions/namespace::*');
            $baseNamespaces = $this->wsdlDomXpath[$wsdlId]->evaluate('//wsdl:definitions/namespace::*');

            $baseUris = [];
            foreach ($baseNamespaces as $ns) {
                $baseUris[] = $ns->namespaceURI;
            }

            foreach ($importedNamespaces as $ns) {
                if (! in_array($ns->namespaceURI, $baseUris) && ! empty($ns->prefix)) {
                    $root = $this->wsdlDomXpath[$wsdlId]->query('//wsdl:definitions')->item(0);
                    if ($root) {
                        $root->setAttributeNS(
                            'http://www.w3.org/2000/xmlns/',
                            'xmlns:'.$ns->prefix,
                            $ns->namespaceURI
                        );
                    }
                }
            }

            // Merge schema imports
            $xsImports = $importedDomXpath->query('//wsdl:definitions/wsdl:types/xs:schema/xs:import');
            $schemaNode = $this->wsdlDomDoc[$wsdlId]->getElementsByTagName('schema')->item(0);

            if ($schemaNode) {
                foreach ($xsImports as $xsImport) {
                    $node = $this->wsdlDomDoc[$wsdlId]->importNode($xsImport, true);
                    $schemaNode->appendChild($node);
                }
            }

            // Merge messages
            $wsdlMessages = $importedDomXpath->query('//wsdl:definitions/wsdl:message');
            $definitionsNode = $this->wsdlDomDoc[$wsdlId]->getElementsByTagName('definitions')->item(0);

            if ($definitionsNode) {
                foreach ($wsdlMessages as $msg) {
                    $node = $this->wsdlDomDoc[$wsdlId]->importNode($msg, true);
                    $definitionsNode->appendChild($node);
                }

                // Merge portTypes
                $portTypes = $importedDomXpath->query('//wsdl:definitions/wsdl:portType');
                foreach ($portTypes as $pt) {
                    $node = $this->wsdlDomDoc[$wsdlId]->importNode($pt, true);
                    $definitionsNode->appendChild($node);
                }
            }
        }
    }

    public function evaluateOnWsdl(string $wsdlId, string $xpath): mixed
    {
        return $this->wsdlDomXpath[$wsdlId]->evaluate($xpath);
    }

    public function loadWsdlXpath(string $wsdlFilePath, string $wsdlId): void
    {
        if (isset($this->wsdlDomXpath[$wsdlId])) {
            return;
        }

        $wsdlContent = file_get_contents($wsdlFilePath);

        if ($wsdlContent === false) {
            throw new InvalidWsdlFileException("WSDL {$wsdlFilePath} could not be loaded");
        }

        $this->wsdlDomDoc[$wsdlId] = new DOMDocument('1.0', 'UTF-8');
        $this->wsdlDomDoc[$wsdlId]->loadXML($wsdlContent);
        $this->wsdlDomXpath[$wsdlId] = new DOMXPath($this->wsdlDomDoc[$wsdlId]);
        $this->wsdlDomXpath[$wsdlId]->registerNamespace('wsdl', 'http://schemas.xmlsoap.org/wsdl/');
        $this->wsdlDomXpath[$wsdlId]->registerNamespace('soap', 'http://schemas.xmlsoap.org/wsdl/soap/');
    }

    protected function extractMessageVersion(string $fullVersionString): string
    {
        $marker = strpos($fullVersionString, '_', strpos($fullVersionString, '_') + 1);

        $num = substr($fullVersionString, $marker + 1);

        return str_replace('_', '.', $num);
    }

    protected function makeWsdlIdentifier(string $wsdlPath): string
    {
        return sprintf('%x', crc32($wsdlPath));
    }
}
