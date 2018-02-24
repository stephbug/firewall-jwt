<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service;

use Illuminate\Http\Request;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use StephBug\SecurityModel\Application\Values\Contract\SecurityIdentifier;
use StephBug\SecurityModel\User\UserSecurity;

interface SecurityFactoryContract extends FactoryContract
{
    public function setUserSecurity(UserSecurity $userSecurity): SecurityFactoryContract;

    public function setRequest(Request $request): SecurityFactoryContract;

    public function getIdentifierFromToken(Token $token): SecurityIdentifier;

    public function getKey(): Key;

    public function setKey(Key $key): SecurityFactoryContract;
}