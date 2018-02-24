<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\FirewallJWT\Application\Values\JWTTokenString;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use Symfony\Component\HttpFoundation\Request;

class JWTAuthenticationRequest implements AuthenticationRequest
{
    public function extract(IlluminateRequest $request): Credentials
    {
        if ($this->matches($request)) {
            return JWTTokenString::fromString($request->bearerToken());
        }

        return null;
    }

    public function matches(Request $request)
    {
        return true;
    }
}