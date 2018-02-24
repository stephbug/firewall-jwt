<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Values;

use Lcobucci\JWT\Token;
use StephBug\SecurityModel\Application\Values\Contract\SecurityIdentifier;

class JWTTokenIdentifier
{
    /**
     * @var Token
     */
    private $token;

    /**
     * @var SecurityIdentifier
     */
    private $identifier;

    public function __construct(Token $token, SecurityIdentifier $identifier)
    {
        $this->token = $token;
        $this->identifier = $identifier;
    }

    public function getToken(): Token
    {
        return $this->token;
    }

    public function getIdentifier(): SecurityIdentifier
    {
        return $this->identifier;
    }
}