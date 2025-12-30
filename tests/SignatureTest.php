<?php

namespace AdGators\ScreenSeed\Webhook\Tests;

use PHPUnit\Framework\TestCase;
use AdGators\ScreenSeed\Webhook\Signature;
use AdGators\ScreenSeed\Webhook\Exceptions\InvalidSignatureFormatException;

class SignatureTest extends TestCase
{
    public function test_validating_signature_format(): void
    {
        $this->assertFalse(Signature::signatureFormatValid('asdf9878asdfjlsdf8a98asdfasdf898'));
        $this->assertFalse(Signature::signatureFormatValid('t=1231245'));
        $this->assertFalse(Signature::signatureFormatValid('v1=asdf9878asdfjlsdf8a98asdfasdf898'));
        $this->assertFalse(Signature::signatureFormatValid('t=123123,v2=asdf9878asdfjlsdf8a98asdfasdf898'));
        $this->assertFalse(Signature::signatureFormatValid('t=123123,v1=aSdf9878AsdfjlsDf8a98asdfasdf898'));
        $this->assertTrue(Signature::signatureFormatValid('t=1693947231,v1=0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b'));
    }

    public function test_initializing_with_invalid_format_throws_exception(): void
    {
        $this->expectException(InvalidSignatureFormatException::class);
        $signature = new Signature('xyz123');
    }

    public function test_getting_timestamp(): void
    {
        $sig = new Signature('t=1693947231,v1=0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b');
        $timestamp = $sig->getTimeStamp();
        $this->assertIsInt($timestamp);
        $this->assertEquals(1693947231, $timestamp);
    }

    public function test_getting_signed_payload(): void
    {
        $sig = new Signature('t=1693947231,v1=0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b');
        $payload = $sig->getSignedPayload();
        $this->assertIsString($payload);
        $this->assertEquals('0a5243d5c397e4e799f0d5ae97aa8426046fe3dc51f654aba7240fba9c5b095b', $payload);
    }

    public function test_signature_match(): void
    {
        $payload = json_encode(['hello' => 'world']);
        $key = '123456abcde';
        $sigStr = Signature::generateTimestampedSignature($payload, $key);

        $sig = new Signature($sigStr);
        $this->assertTrue($sig->matches($payload, $key));
    }

    public function test_signature_timestamp_threshold(): void
    {
        $sigTime = time() - 15;
        $payload = json_encode(['hello' => 'world']);
        $key = '123456abcde';
        $hmac = Signature::generateHmac($sigTime, $payload, $key);
        $sigStr = "t={$sigTime},v1={$hmac}";

        $sig = new Signature($sigStr);
        $this->assertTrue($sig->matches($payload, $key));
        $this->assertFalse($sig->newerThan(10));
        $this->assertTrue($sig->newerThan(30));
    }

    public function test_future_timestamp_is_invalid(): void
    {
        $future = time() + 30;
        $payload = 'test';
        $key = 'secret';

        $hmac = Signature::generateHmac($future, $payload, $key);
        $sig = new Signature("t={$future},v1={$hmac}");

        $this->assertFalse($sig->newerThan(10));
    }

    public function test_signature_does_not_match_modified_payload(): void
    {
        $payload = '{"hello":"world"}';
        $key = 'secret';

        $sigStr = Signature::generateTimestampedSignature($payload, $key);
        $sig = new Signature($sigStr);

        $this->assertFalse(
            $sig->matches('{"hello":"tampered"}', $key)
        );
    }

    public function test_signature_does_not_match_with_wrong_secret(): void
    {
        $payload = 'test';
        $sigStr = Signature::generateTimestampedSignature($payload, 'correct-secret');

        $sig = new Signature($sigStr);

        $this->assertFalse(
            $sig->matches($payload, 'wrong-secret')
        );
    }

    public function test_signature_exactly_at_threshold_fails(): void
    {
        $timestamp = time() - 30;
        $payload = 'test';
        $key = 'secret';

        $hmac = Signature::generateHmac($timestamp, $payload, $key);
        $sig = new Signature("t={$timestamp},v1={$hmac}");

        $this->assertFalse($sig->newerThan(30));
    }
}
