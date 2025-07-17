<?php
/**
 * @file
 * login.php
 *
 * @brief Handles user authentication.
 *
 * This script accepts a POST request with a username and password, validates the
 * credentials against a MySQL database, and returns a JWT if authentication is successful.
 * The JWT contains user information and an expiration time.
 */

// Disable error display for production environments and report no errors.
ini_set('display_errors', 0);
error_reporting(0);

header('Content-Type: application/json');
$config_file = __DIR__ . '/config.php';

// Check if the configuration file exists.
if (!file_exists($config_file)) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Server configuration error."]);
    exit;
}

// Load configuration and establish database connection.
$config = require_once $config_file;
$conn = new mysqli($config['db_server'], $config['db_username'], $config['db_password'], $config['db_name']);

// Check for database connection errors.
if ($conn->connect_error) {
    http_response_code(500);
    error_log("Database connection failed: " . $conn->connect_error);
    echo json_encode(["success" => false, "message" => "An unexpected error occurred. Please try again later."]);
    exit;
}

$secret_key = $config['jwt_secret_key'];

/**
 * @brief Encodes a string into a Base64url-safe format.
 *
 * Replaces standard Base64 characters ('+', '/', '=') with URL-safe equivalents ('-', '_', '').
 *
 * @param string $data The string to encode.
 * @return string The Base64url-encoded string.
 */
function base64url_encode($data) {
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

/**
 * @brief Creates a new JSON Web Token (JWT).
 *
 * Generates a JWT by creating a header, a payload, and a signature using HMAC-SHA256.
 * The header and payload are Base64url-encoded.
 *
 * @param array $payload The data to be included in the token's payload.
 * @param string $secret The secret key used to sign the token.
 * @return string The complete JWT string.
 */
function create_jwt($payload, $secret) {
    $header = base64url_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64url_encode(json_encode($payload));
    return "$header.$payload." . base64url_encode(hash_hmac('sha256', "$header.$payload", $secret, true));
}

// Check if the request method is POST.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["success" => false, "message" => "Method not allowed. Only POST requests are accepted."]);
    exit;
}

// Retrieve and validate username and password from the POST data.
$username = trim($_POST['username'] ?? '');
$password = trim($_POST['password'] ?? '');
if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Username and password are required."]);
    exit;
}

// Prepare and execute a SQL statement to retrieve the user's details.
$stmt = $conn->prepare("SELECT username, password, display_name FROM users WHERE username = ?");
if (!$stmt) {
    http_response_code(500);
    error_log("Database statement preparation failed (select): " . $conn->error);
    echo json_encode(["success" => false, "message" => "An unexpected error occurred."]);
    exit;
}
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

// Verify user existence and password.
if ($result->num_rows === 0 || !password_verify($password, ($user = $result->fetch_assoc())['password'])) {
    http_response_code(401);
    echo json_encode(["success" => false, "message" => "Invalid username or password."]);
} else {
    // On successful login, create a JWT with a 14-days expiration.
    $jwt = create_jwt(['username' => $user['username'], 'display_name' => $user['display_name'], 'iat' => time(), 'exp' => time() + 1209600], $secret_key);
    http_response_code(200);
    echo json_encode(["success" => true, "message" => "Login successful!", "jwt" => $jwt]);
}

// Close resources.
$stmt->close();
$conn->close();
?>