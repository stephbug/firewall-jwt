<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Http\Firewall;

use Illuminate\Http\Request;
use StephBug\FirewallJWT\Guard\Authentication\Token\JWTToken;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Http\Entrypoint\Entrypoint;
use StephBug\SecurityModel\Application\Http\Firewall\AuthenticationFirewall;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use StephBug\SecurityModel\Application\Values\NullIdentifier;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityModel\User\Exception\BadCredentials;
use Symfony\Component\HttpFoundation\Response;

class JWTAuthenticationFirewall extends AuthenticationFirewall
{
    /**
     * @var Guard
     */
    private $guard;

    /**
     * @var Entrypoint
     */
    private $entrypoint;

    /**
     * @var AuthenticationRequest
     */
    private $authenticationRequest;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    public function __construct(Guard $guard,
                                Entrypoint $entrypoint,
                                AuthenticationRequest $authenticationRequest,
                                SecurityKey $securityKey)
    {
        $this->guard = $guard;
        $this->entrypoint = $entrypoint;
        $this->authenticationRequest = $authenticationRequest;
        $this->securityKey = $securityKey;
    }

    protected function processAuthentication(Request $request): ?Response
    {
        try {
            $token = $this->guard->authenticate(
                $this->createToken($request)
            );

            $this->guard->put($token);

            return null;
        } catch (AuthenticationException $exception) {
            return $this->entrypoint->startAuthentication($request, $exception);
        }
    }

    protected function requireAuthentication(Request $request): bool
    {
        return $this->guard->isStorageEmpty();
    }

    protected function createToken(Request $request): Tokenable
    {
        if (!$credential = $this->authenticationRequest->extract($request)) {
            throw BadCredentials::invalid();
        }

        return new JWTToken(new NullIdentifier(), $credential, $this->securityKey);
    }
}