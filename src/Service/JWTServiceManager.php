<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service;

use Illuminate\Contracts\Foundation\Application;
use StephBug\FirewallJWT\Service\Provider\JWTProvider;

class JWTServiceManager
{
    /**
     * @var Application
     */
    private $app;

    /**
     * @var array
     */
    protected $providers = [];

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function make(string $name): JWTProvider
    {
        if (isset($this->providers[$name])) {
            return $this->providers[$name];
        }

        if (!$this->hasService($name)) {
            throw new \RuntimeException(sprintf('Jwt service %s does not exists', $name));
        }

        $config = $this->getConfig()[$name];

        return $this->providers[$name] = $this->create($config['service'], $config['config']);
    }

    protected function create(string $serviceId, callable $config): JWTProvider
    {
        if ($this->app->bound($serviceId)) {
            $id = $this->app->make($serviceId);
        } else {
            $id = $config($this->app->make($serviceId));
        }

        if (method_exists($id, 'setRequest')) {
            $id->setRequest($this->app->refresh('request', $id, 'setRequest'));
        }

        return new JWTFactory($id);
    }

    public function hasService(string $providerName): bool
    {
        return null !== array_get($this->getConfig(), $providerName);
    }

    protected function getConfig(): array
    {
        return $this->app->make('config')->get('security_jwt.services', []);
    }
}