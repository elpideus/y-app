<?php
/**
 * @file
 * register.php
 *
 * @brief Handles new user registration.
 *
 * This script accepts a POST request with user data, checks for username availability,
 * hashes the password, inserts the new user into the database, and returns a JWT.
 */
header('Content-Type: application/json');

$config_file = __DIR__ . '/config.php';

// Check if the configuration file exists.
if (!file_exists($config_file)) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Server configuration error."]);
    exit;
}

$config = require_once $config_file;
$conn = new mysqli($config['db_server'], $config['db_username'], $config['db_password'], $config['db_name']);

// Check for database connection errors.
if ($conn->connect_error) {
    http_response_code(500);
    error_log("Database connection failed: " . $conn->connect_error);
    echo json_encode(["success" => false, "message" => "Database connection error."]);
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
    echo json_encode(["success" => false, "message" => "Only POST requests are accepted."]);
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

// Check if the username is already taken.
$stmt = $conn->prepare("SELECT username FROM users WHERE username = ?");
if (!$stmt) {
    http_response_code(500);
    error_log("Prepare failed (check): " . $conn->error);
    echo json_encode(["success" => false, "message" => "An unexpected error occurred."]);
    exit;
}
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    http_response_code(409); // Conflict
    echo json_encode(["success" => false, "message" => "This username is already taken."]);
    $stmt->close();
    exit;
}
$stmt->close();

// Hash the password for secure storage.
$hashed_password = password_hash($password, PASSWORD_BCRYPT);
if (!$hashed_password) {
    http_response_code(500);
    error_log("Password hashing failed for: $username");
    echo json_encode(["success" => false, "message" => "Password hashing failed."]);
    exit;
}

// Prepare the display name (defaults to username if not provided).
$display_name = trim($_POST['display_name'] ?? $username);

// Prepare and execute the SQL statement to insert the new user.
$stmt = $conn->prepare("INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)");
if (!$stmt) {
    http_response_code(500);
    error_log("Prepare failed (insert): " . $conn->error);
    echo json_encode(["success" => false, "message" => "An unexpected error occurred."]);
    exit;
}
$stmt->bind_param("sss", $username, $hashed_password, $display_name);

// If insertion is successful, create a JWT and return a success message.
if ($stmt->execute()) {
    $jwt = create_jwt(['username' => $username, 'display_name' => $display_name, 'iat' => time(), 'exp' => time() + 1209600], $secret_key);
    http_response_code(200);
    echo json_encode(["success" => true, "message" => "User registered successfully!", "jwt" => $jwt]);
} else {
    http_response_code(500);
    error_log("Insert failed: " . $stmt->error);
    echo json_encode(["success" => false, "message" => "Failed to register user."]);
}

// Close resources.
$stmt->close();
$conn->close();
?>