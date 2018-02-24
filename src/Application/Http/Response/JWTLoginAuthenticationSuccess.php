<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Http\Response;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use StephBug\FirewallJWT\Service\Provider\JWTProvider;
use StephBug\SecurityModel\Application\Http\Response\AuthenticationSuccess;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use Symfony\Component\HttpFoundation\Response;

class JWTLoginAuthenticationSuccess implements AuthenticationSuccess
{
    /**
     * @var JWTProvider
     */
    private $provider;

    public function __construct(JWTProvider $provider)
    {
        $this->provider = $provider;
    }

    public function onAuthenticationSuccess(Request $request, Tokenable $token): Response
    {
        return new JsonResponse([
            'message' => 'Login successful',
            'data' => [
                'token' => (string)$this->provider->create($token->getUser()),
                'refresh_token' => null
            ]
        ]);
    }
}