<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;

interface FactoryContract
{
    public function setBuilder(Builder $builder): FactoryContract;

    public function getBuilder(): Builder;

    public function setSigner(Signer $signer): FactoryContract;

    public function getSigner(): Signer;

    public function setParser(Parser $parser): FactoryContract;

    public function getParser(): Parser;

    public function setValidationData(ValidationData $validationData): FactoryContract;

    public function getValidationData(): ValidationData;
}