<?php
/**
 * @file
 * auth_jwt.php
 *
 * @brief This script provides a RESTful API endpoint for authenticating a user
 * based on a JSON Web Token (JWT) provided in the HTTP Authorization header.
 * It validates the token's format, signature, and expiration time.
 *
 * If the token is valid, it returns a success message along with user details
 * extracted from the token's payload. Otherwise, it returns an appropriate
 * error message and HTTP status code.
 *
 * @dependency config.php - A separate PHP file that must exist in the same
 * directory and contain the 'jwt_secret_key'.
 *
 * @example
 * Request with a valid token:
 * GET /auth_jwt.php
 * Authorization: Bearer eyJhbGciOiJIUzI1NiI...
 *
 * Response:
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * {
 * "success": true,
 * "message": "Token is valid.",
 * "user": {
 * "username": "testuser",
 * "display_name": "Test User"
 * }
 * }
 */
header('Content-Type: application/json');

// Define the path to the configuration file and load it.
$config_file = __DIR__ . '/config.php';

// Check for server configuration errors (e.g., missing config file).
if (!file_exists($config_file)) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Server configuration error."]);
    exit();
}

$config = require_once $config_file;
$secret_key = $config['jwt_secret_key'];

/**
 * @brief Decodes a Base64url-encoded string.
 *
 * This function handles the URL-safe Base64 variant, which replaces '+' with '-'
 * and '/' with '_', and omits padding. It also adds padding back if necessary
 * before decoding.
 *
 * @param string $data The Base64url-encoded string.
 * @return string The decoded binary string.
 */
function base64url_decode($data) {
    $base64 = str_replace(['-', '_'], ['+', '/'], $data);
    return base64_decode($base64 . str_repeat('=', 4 - strlen($base64) % 4));
}

/**
 * @brief Validates the signature of a JWT.
 *
 * This function verifies if the JWT's signature is correct by re-calculating the
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

    /* Compare the calculated signature with the signature from the token using hash_equals for a timing-attack-safe
    comparison. */
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

// --- Main Script Execution Flow ---

// 1. Check HTTP request method.
// Only GET and POST methods are allowed. Return 405 Method Not Allowed for others.
if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["success" => false, "message" => "Method not allowed. Only GET and POST requests are accepted."]);
    exit();
}

// 2. Extract the JWT from the Authorization header.
// It checks for the "Authorization: Bearer <token>" format.
$jwt = '';
$auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? (function_exists('getallheaders') ? getallheaders()['Authorization'] ?? '' : ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
if (!preg_match('/Bearer\s(\S+)/', $auth_header, $matches)) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => "Unauthorized: No token provided."]);
    exit();
}
$jwt = $matches[1];

// 3. Validate the JWT signature.
// A tampered token will fail this check.
if (!is_jwt_valid($jwt, $secret_key)) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => "Unauthorized: Invalid token."]);
    exit();
}

// 4. Decode the token payload and check for expiration.
$payload = decode_jwt_payload($jwt);
if ($payload === false || (isset($payload['exp']) && $payload['exp'] < time())) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => $payload === false ? "Unauthorized: Invalid token payload." : "Unauthorized: Token has expired."]);
    exit();
}

// 5. If all checks pass, the token is valid. Return success.
http_response_code(200);
echo json_encode(["success" => true, "message" => "Token is valid.", "user" => ["username" => $payload['username'] ?? '', "display_name" => $payload['display_name'] ?? '']]);
?>