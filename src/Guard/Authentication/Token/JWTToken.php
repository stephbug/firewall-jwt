<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Guard\Authentication\Token;

use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\Contract\UserToken;
use StephBug\SecurityModel\Guard\Authentication\Token\Token;

class JWTToken extends Token
{
    /**
     * @var Credentials
     */
    private $credentials;

    public function __construct(UserToken $user, Credentials $credentials, array $roles = [])
    {
        parent::__construct($roles);

        $this->setUser($user);
        $this->credentials = $credentials;

        count($roles) > 0 and $this->setAuthenticated(true);
    }

    public function getCredentials(): Credentials
    {
        return $this->credentials;
    }
}