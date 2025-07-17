<?php
/**
 * @file
 * validate_session.php
 *
 * @brief Validates a user's session based on a JWT provided in the Authorization header.
 *
 * This script is a REST API endpoint that checks if a given JWT is valid,
 * not expired, and correctly signed. If all checks pass, it confirms the
 * session's validity.
 */
header('Content-Type: application/json');

$config_file = __DIR__ . '/config.php';

// Check for the configuration file.
if (!file_exists($config_file)) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Server configuration error."]);
    exit;
}

$config = require_once $config_file;
$secret_key = $config['jwt_secret_key'];

/**
 * @brief Decodes a Base64url-encoded string.
 *
 * Handles the URL-safe Base64 variant, which replaces '+' with '-' and '/' with '_',
 * and omits padding. It adds padding back if necessary before decoding.
 *
 * @param string $data The Base64url-encoded string.
 * @return string The decoded binary string.
 */
function base64url_decode($data) {
    $base64 = str_replace(['-', '_'], ['+', '/'], $data);
    return base64_decode($base64 . str_repeat('=', 4 - (strlen($base64) % 4)));
}

/**
 * @brief Validates the signature of a JWT.
 *
 * This function verifies if the JWT's signature is correct by recalculating the
 * HMAC-SHA256 signature and comparing it in a timing-attack-safe manner.
 *
 * @param string $jwt The full JWT string (header.payload.signature).
 * @param string $secret The secret key used to sign the token.
 * @return bool True if the signature is valid, false otherwise.
 */
function is_jwt_valid($jwt, $secret) {
    // A regular expression is used to ensure the JWT has the correct format of three parts.
    if (!preg_match('/^([a-zA-Z0-9\-\_]+)\.([a-zA-Z0-9\-\_]+)\.([a-zA-Z0-9\-\_]+)$/', $jwt, $matches)) return false;
    list(, $encodedHeader, $encodedPayload, $encodedSignature) = $matches;

    // Recalculate the signature using the header, payload, and secret key.
    $signature = hash_hmac('sha256', "$encodedHeader.$encodedPayload", $secret, true);

    // Compare the calculated signature with the token's signature using hash_equals
    // for a timing-attack-safe comparison.
    return hash_equals($signature, base64url_decode($encodedSignature));
}

/**
 * @brief Decodes the payload portion of a JWT.
 *
 * This function splits the JWT into its three parts and decodes the payload
 * (the second part) from Base64url-encoded JSON.
 *
 * @param string $jwt The full JWT string.
 * @return array|false The decoded payload as an associative array, or false if
 * decoding fails or the token format is incorrect.
 */
function decode_jwt_payload($jwt) {
    $parts = explode('.', $jwt);
    return count($parts) !== 3 ? false : json_decode(base64url_decode($parts[1]), true);
}

// Check for allowed HTTP methods.
if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["success" => false, "message" => "Method not allowed. Only GET and POST requests are accepted."]);
    exit;
}

// Extract the JWT from the Authorization header.
$auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? (function_exists('getallheaders') ? getallheaders()['Authorization'] ?? '' : ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
if (!preg_match('/Bearer\s(\S+)/', $auth_header, $matches)) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => "Unauthorized: No token provided."]);
    exit;
}
$jwt = $matches[1];

// Validate the JWT signature.
if (!is_jwt_valid($jwt, $secret_key)) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => "Unauthorized: Invalid token."]);
    exit;
}

// Decode the payload and check if the token has expired.
$payload = decode_jwt_payload($jwt);
if ($payload === false || (isset($payload['exp']) && $payload['exp'] < time())) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => $payload === false ? "Unauthorized: Invalid token payload." : "Unauthorized: Token has expired."]);
    exit;
}

// If all checks pass, the token is valid.
http_response_code(200);
echo json_encode(["success" => true, "message" => "Token is valid.", "user" => ["username" => $payload['username'] ?? '', "display_name" => $payload['display_name'] ?? '']]);
?>