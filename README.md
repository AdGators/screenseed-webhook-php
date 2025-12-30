# ScreenSeed Webhook Verification (PHP)

![Tests](https://github.com/adgators/screenseed-webhook/actions/workflows/tests.yml/badge.svg)
![PHP Version](https://img.shields.io/badge/php-%3E%3D8.0-blue)
![License](https://img.shields.io/github/license/adgators/screenseed-webhook)

PHP utilities for verifying **ScreenSeed** webhook signatures.

This package helps you:
- Validate webhook signatures securely
- Prevent replay attacks
- Safely compare HMACs using constant-time comparison

---

## Installation

```bash
composer require adgators/screenseed-webhook
```
## Usage

```php
use AdGators\ScreenSeed\Webhook\Signature;
use AdGators\ScreenSeed\Webhook\Exceptions\InvalidSignatureFormatException;

$payload = file_get_contents('php://input');
$signatureHeader = $_SERVER['HTTP_SCREENSEED_SIGNATURE'];
$secret = $_ENV['SCREENSEED_WEBHOOK_SECRET'];

try {
    $signature = new Signature($signatureHeader);

    // verify the signature matches and is less than 30 seconds old
    if (! $signature->verify($payload, $secret, 30)) {
        http_response_code(401);
        exit('Invalid webhook signature');
    }
}
catch(InvalidSignatureFormatException $e) {
    exit($e->getMessage());
}
```

## License

MIT © AdGators
