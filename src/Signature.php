<?php

namespace AdGators\ScreenSeed\Webhook;

use AdGators\ScreenSeed\Webhook\Exceptions\InvalidSignatureFormatException;

class Signature
{
    // Example: 't=1693947231,v1=0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b'
    const EXPECTED_FORMAT = '/^t=\d+,v1=[a-f0-9]{64}$/';

    // Given signature containing the timestamp and signed payload
    protected string $signature;

    // Timestamp at the time the instance of this class is created
    protected int $now;

    /**
     * @param  string  $signature  - the given signature to be checked
     *
     * @throws InvalidSignatureFormatException
     */
    public function __construct(string $signature)
    {
        if (! self::signatureFormatValid($signature)) {
            throw new InvalidSignatureFormatException;
        }
        $this->signature = $signature;
        $this->now = (new \DateTime)->getTimestamp();
    }

    /**
     * Helper method that verifies the payload matches and is newer than the given maxAge
     */
    public function verify(string $payload, string $secret, int $maxAgeSeconds): bool
    {
        return $this->matches($payload, $secret)
            && $this->newerThan($maxAgeSeconds);
    }

    /**
     * Check if the provided payload (usually the request body) and secret key match that of the signature
     */
    public function matches(string $payload, string $secretKey): bool
    {
        return hash_equals($this->getSignedPayload(), static::generateHmac($this->getTimeStamp(), $payload, $secretKey));
    }

    /**
     * Check if the difference between now and the signature timestamp is less than given seconds
     */
    public function newerThan(int $seconds): bool
    {
        $diff = $this->timestampDiff();
        return $diff >= 0 && $diff < $seconds;
    }

    /**
     * Returns the number of seconds elapsed since the timestamp on the signature
     */
    public function timestampDiff(): int
    {
        return $this->now - $this->getTimeStamp();
    }

    /**
     * Returns the timestamp portion of the signature as an int
     */
    public function getTimeStamp(): int
    {
        return intval($this->getSignatureTokens()[0][1]);
    }

    /**
     * Returns the signed payload portion of the signature
     */
    public function getSignedPayload(): string
    {
        return $this->getSignatureTokens()[1][1];
    }

    /**
     * Get pieces of the signature as an array
     * example result: [['t', '1693947231'], ['v1', '0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b']]
     */
    protected function getSignatureTokens(): array
    {
        return array_map(fn ($val) => explode('=', $val), explode(',', $this->signature));
    }

    /**
     * Check if the given signature is in the expected format
     */
    public static function signatureFormatValid(string $signature): bool
    {
        return preg_match(static::EXPECTED_FORMAT, $signature);
    }

    /**
     * Generates an HMAC with the SHA256 hash with the given timestamp, payload, and key
     */
    public static function generateHmac(int $timestamp, string $payload, string $secretKey): string
    {
        return hash_hmac('sha256', "{$timestamp}.{$payload}", $secretKey);
    }

    public static function generateTimestampedSignature(string $payload, string $secretKey): string
    {
        $timestamp = (new \DateTime)->getTimestamp();
        $hmac = static::generateHmac($timestamp, $payload, $secretKey);

        return "t={$timestamp},v1={$hmac}";
    }
}
