<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service;

use Lcobucci\JWT\Token;
use StephBug\FirewallJWT\Application\Values\JWTTokenIdentifier;
use StephBug\FirewallJWT\Application\Values\JWTTokenString;
use StephBug\FirewallJWT\Service\Provider\JWTProvider;
use StephBug\SecurityModel\User\Exception\BadCredentials;
use StephBug\SecurityModel\User\UserSecurity;

class JWTFactory implements JWTProvider
{
    /**
     * @var SecurityFactoryContract
     */
    private $configuration;

    public function __construct(SecurityFactoryContract $configuration)
    {
        $this->configuration = $configuration;
    }

    public function create(UserSecurity $user): Token
    {
        $this->configuration->setUserSecurity($user);

        return $this->configuration
            ->getBuilder()
            ->sign($this->configuration->getSigner(), $this->configuration->getKey())
            ->getToken();
    }

    public function getJwtToken(JWTTokenString $tokenString): JWTTokenIdentifier
    {
        $token = $this->configuration->getParser()->parse($tokenString->credentials());

        $this->check($token);

        return new JWTTokenIdentifier($token, $this->configuration->getIdentifierFromToken($token));
    }

    private function check(Token $token): void
    {
        $this->verifySignature($token);

        $this->validate($token);
    }

    private function validate(Token $token): bool
    {
        if ($token->validate($this->configuration->getValidationData())) {
            return true;
        }

        throw BadCredentials::invalid('JWT token validation failed');
    }

    private function verifySignature(Token $token): bool
    {
        if ($token->verify($this->configuration->getSigner(), $this->configuration->getKey())) {
            return true;
        }

        throw BadCredentials::invalid('JWT token is invalid');
    }
}