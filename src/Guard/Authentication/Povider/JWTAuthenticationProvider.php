<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Guard\Authentication\Povider;

use StephBug\FirewallJWT\Guard\Authentication\Token\JWTToken;
use StephBug\FirewallJWT\Service\Provider\JWTProvider;
use StephBug\SecurityModel\Application\Exception\UnsupportedProvider;
use StephBug\SecurityModel\Application\Values\EmptyCredentials;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Providers\AuthenticationProvider;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\User\Exception\BadCredentials;
use StephBug\SecurityModel\User\UserProvider;

class JWTAuthenticationProvider implements AuthenticationProvider
{
    /**
     * @var UserProvider
     */
    private $userProvider;

    /**
     * @var JWTProvider
     */
    private $manager;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    public function __construct(UserProvider $userProvider, JWTProvider $manager, SecurityKey $securityKey)
    {
        $this->userProvider = $userProvider;
        $this->manager = $manager;
        $this->securityKey = $securityKey;
    }

    public function authenticate(Tokenable $token): Tokenable
    {
        if (!$this->supports($token)) {
            throw UnsupportedProvider::withSupport($token, $this);
        }

        $tokenString = $token->getCredentials();

        if ($tokenString instanceof EmptyCredentials) {
            throw BadCredentials::invalid($tokenString);
        }

        $jwtToken = $this->manager->getJwtToken($tokenString);

        $user = $this->userProvider->requireByIdentifier($jwtToken->getIdentifier());

        return new JWTToken($user, $tokenString, $this->securityKey);
    }

    public function supports(Tokenable $token): bool
    {
        return $token instanceof JWTToken && $this->securityKey->sameValueAs($token->getSecurityKey());
    }
}