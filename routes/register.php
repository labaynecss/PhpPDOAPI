<?php
require_once '../models/database.php';
require_once '../vendor/autoload.php';
require_once __DIR__ . '/../src/CorsPolicy.php';

$corsPolicy = new CorsPolicy();
$corsPolicy->cors();

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../'); // Specify the path to your .env file
$dotenv->load(); // Load the environment variables


if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    header("Allow: POST");
    exit;
}
// After loading the environment variables, you can now access them
$host = $_ENV['DB_HOST'];
$name = $_ENV['DB_NAME'];
$user = $_ENV['DB_USER'];
$pass = $_ENV['DB_PASS'];

$data = (array) json_decode(file_get_contents("php://input"), true);

// Get the required parameters from the POST request
$username = $data['username'] ?? null;
$password = $data['password'] ?? null;
$email = $data['email'] ?? null;
$firstName = $data['firstName'] ?? null;
$middleName = $data['middleName'] ?? null;
$lastName = $data['lastName'] ?? null;

if ($username === null || $password === null || $email === null || $firstName === null || $lastName === null) {
    // Required parameters are missing
    http_response_code(400);
    $response = [
        'message' => 'Missing required parameters'
    ];
    header('Content-Type: application/json');
    echo json_encode($response); 
    exit;
}

try {
    $conn = new PDO("mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']}", $_ENV['DB_USER'], $_ENV['DB_PASS']);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Check if username or email already exists in the database
    $stmt = $conn->prepare("SELECT * FROM tbl_user_profile WHERE user_name = :username OR user_email = :email");
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        // User with the same username or email already exists
        http_response_code(409);
        $response = [
            'message' => 'Username or email already exists'
        ];
    } else {
        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Insert the new user into the database
        $stmt = $conn->prepare("INSERT INTO tbl_user_profile (user_name, user_password, user_email, user_first_name, user_middle_name, user_last_name, user_status, user_department, delete_status, api_key) 
        VALUES (:username, :password, :email, :firstName, :middleName, :lastName, 'active', 'department', 'active', 'api_key')");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->bindParam(':password', $hashedPassword, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':firstName', $firstName, PDO::PARAM_STR);
        $stmt->bindParam(':middleName', $middleName, PDO::PARAM_STR);
        $stmt->bindParam(':lastName', $lastName, PDO::PARAM_STR);
        $stmt->execute();

        http_response_code(201);
        $response = [
            'message' => 'Registration successful'
        ];
    }
} catch (PDOException $e) {
    http_response_code(500);
    $response = [
        'message' => 'Database connection error: ' . $e->getMessage()
    ];
}

// Set the response headers to return JSON
header('Content-Type: application/json');
echo json_encode($response);
?>