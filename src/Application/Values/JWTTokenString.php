<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Values;

use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\Contract\SecurityValue;
use StephBug\SecurityModel\Application\Values\EmptyCredentials;

class JWTTokenString implements Credentials
{
    /**
     * @var string
     */
    private $token;

    private function __construct(string $token)
    {
        $this->token = $token;
    }

    public static function fromString($token): Credentials
    {
        if (null === $token || (is_string($token) && empty($token))) {
            return new EmptyCredentials();
        }

        return new self($token);
    }

    public function credentials(): string
    {
        return $this->token;
    }

    public function sameValueAs(SecurityValue $aValue): bool
    {
        return $aValue instanceof $this && $this->token === $aValue->credentials();
    }
}