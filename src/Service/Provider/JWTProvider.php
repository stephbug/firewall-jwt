<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service\Provider;

use Lcobucci\JWT\Token;
use StephBug\FirewallJWT\Application\Values\JWTTokenIdentifier;
use StephBug\FirewallJWT\Application\Values\JWTTokenString;
use StephBug\SecurityModel\User\UserSecurity;

interface JWTProvider
{
    public function create(UserSecurity $user): Token;

    public function getJwtToken(JWTTokenString $tokenString): JWTTokenIdentifier;
}