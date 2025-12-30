<?php

namespace AdGators\ScreenSeed\Webhook\Exceptions;

class InvalidSignatureFormatException extends \Exception
{
    protected $message = 'The provided ScreenSeed signature format is invalid.';
}
