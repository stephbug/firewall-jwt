<?php

return [

    'services' => [
        'api.jwt' => [
            'matcher' => '*api',
            'service' => \StephBug\FirewallJWT\Service\Example\Configuration::class,
            'config' => function(\StephBug\FirewallJWT\Service\SecurityFactoryContract $config){
                $config->setSigner(new \Lcobucci\JWT\Signer\Hmac\Sha256());
                $config->setKey(new \Lcobucci\JWT\Signer\Key('testing'));
            }
        ]
    ]
];