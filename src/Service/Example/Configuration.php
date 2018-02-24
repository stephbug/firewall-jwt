<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service\Example;

use Illuminate\Http\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use StephBug\FirewallJWT\Service\FactoryContract;
use StephBug\FirewallJWT\Service\SecurityFactoryContract;
use StephBug\SecurityModel\Application\Values\Contract\SecurityIdentifier;
use StephBug\SecurityModel\Application\Values\EmailAddress;
use StephBug\SecurityModel\User\UserSecurity;

class Configuration implements SecurityFactoryContract
{
    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var Builder
     */
    private $builder;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var ValidationData
     */
    private $validationData;

    /**
     * @var Key
     */
    private $key;

    /**
     * @var UserSecurity
     */
    private $userSecurity;

    /**
     * @var Request
     */
    private $request;

    public function getBuilder(): Builder
    {
        return (new Builder(null, $this->getFactoryClaims()))
            ->setIssuer(config('app.url'))
            ->setAudience('api')
            ->setIssuedAt(time());
    }

    public function getValidationData(): ValidationData
    {
        $data = new ValidationData();
        $data->setIssuer(config('app.url'));
        $data->setAudience('api');

        return $data;
    }

    public function setUserSecurity(UserSecurity $userSecurity): SecurityFactoryContract
    {
        $this->userSecurity = $userSecurity;

        return $this;
    }

    public function setRequest(Request $request): SecurityFactoryContract
    {
        $this->request = $request;

        return $this;
    }

    public function getIdentifierFromToken(Token $token): SecurityIdentifier
    {
        return EmailAddress::fromString($token->getClaim('uid'));
    }

    private function getFactoryClaims(): Factory
    {
        return new Factory([
            'uid' => [Factory::class, 'createEqualsTo']
        ]);
    }

    public function setBuilder(Builder $builder): FactoryContract
    {
        $this->builder = $builder;

        return $this;
    }

    public function setSigner(Signer $signer): FactoryContract
    {
        $this->signer = $signer;

        return $this;
    }

    public function getSigner(): Signer
    {
        return $this->signer;
    }

    public function setParser(Parser $parser): FactoryContract
    {
        $this->parser = $parser;

        return $this;
    }

    public function getParser(): Parser
    {
        return $this->parser ?? new Parser();
    }

    public function setValidationData(ValidationData $validationData): FactoryContract
    {
        $this->validationData = $validationData;

        return $this;
    }

    public function getKey(): Key
    {
        return $this->key;
    }

    public function setKey(Key $key): SecurityFactoryContract
    {
        $this->key = $key;

        return $this;
    }
}