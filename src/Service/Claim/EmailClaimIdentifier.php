<?php

declare(strict_types=1);

namespace StephBug\FirewallJWT\Service\Claim;

use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Claim\Validatable;
use Lcobucci\JWT\ValidationData;
use StephBug\SecurityModel\Application\Values\Contract\EmailAddress as EmailContract;
use StephBug\SecurityModel\Application\Values\Contract\SecurityIdentifier;
use StephBug\SecurityModel\Application\Values\Contract\SecurityValue;
use StephBug\SecurityModel\Application\Values\EmailAddress;

class EmailClaimIdentifier extends Basic implements SecurityIdentifier, Validatable
{
    public function identify(): string
    {
        return $this->getValue();
    }

    public function sameValueAs(SecurityValue $aValue): bool
    {
        return $aValue instanceof $this
            && $this->getName() === $aValue->getName()
            && $this->getValue() === $aValue->getValue();
    }

    public function getIdentifier(): EmailContract
    {
        return EmailAddress::fromString($this->getValue());
    }

    public function validate(ValidationData $data)
    {
        if ($data->has($this->getName())) {
            return $this->getValue() === $data->get($this->getName());
        }

        return true;
    }
}