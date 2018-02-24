<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Application\Providers;

use Illuminate\Support\ServiceProvider;
use StephBug\FirewallJWT\Service\JWTServiceManager;

class FirewallJWTServiceProvider extends ServiceProvider
{
    /**
     * @var bool
     */
    protected $defer = true;

    public function boot(): void
    {
        $this->publishes(
            [$this->getConfigPath() => config_path('security_jwt.php')],
            'config'
        );
    }

    public function register(): void
    {
        $this->mergeConfig();

        $this->app->singleton(JWTServiceManager::class);
    }

    public function provides(): array
    {
        return [JWTServiceManager::class];
    }

    protected function mergeConfig(): void
    {
        $this->mergeConfigFrom($this->getConfigPath(), 'security_jwt');
    }

    protected function getConfigPath(): string
    {
        return __DIR__ . '/../../../config/security_jwt.php';
    }
}