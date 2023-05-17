<?php
require_once '../models/database.php';
require_once '../vendor/autoload.php';
require_once __DIR__ . '/../src/CorsPolicy.php';
require_once __DIR__ . '/../src/JWTCodec.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$secretKey = $_ENV['SECRET_KEY'];
$jwtCodec = new JWTCodec($secretKey);
$corsPolicy = new CorsPolicy();
$corsPolicy->cors();

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

$username = $data['username'] ?? null;
$password = $data['password'] ?? null;
// Verify if the password is correct
if ($username === null || $password === null) {
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

    $stmt = $conn->prepare("SELECT * FROM tbl_user_profile WHERE user_name = :username");
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->execute();

    if ($stmt->rowCount() === 1) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $hashedPassword = $row['user_password'];

          // Verify if the password is correct
        if (password_verify($password, $hashedPassword)) {
            
            $payload = [
                'username' => $row['user_name'],
                'email' => $row['user_email'],
                'firstName' => $row['user_first_name'],
                'lastName' => $row['user_last_name'],
            ];
            // Generate the token
            $token = $jwtCodec->encode($payload);
        // Correct password, perform login
            http_response_code(200);
            $response = [
                'message' => 'Login successful',
                'token' => $token,
                'user' => [
                    'username' => $row['user_name'],
                    'email' => $row['user_email'],
                    'firstName' => $row['user_first_name'],
                    'middleName' => $row['user_middle_name'],
                    'lastName' => $row['user_last_name']
                ]
            ];
        } else {
            // Invalid password
            http_response_code(401);
            $response = [
                'message' => 'Invalid password'
            ];
        }
    } else {
         // User not found in the database
        http_response_code(404);
        $response = [
            'message' => 'User not found'
        ];
    }
} catch (PDOException $e) {
    http_response_code(500);
    $response = [
        'message' => 'Database connection error: ' . $e->getMessage()
    ];
}

$conn = null;

// Set the response headers to return JSON
header('Content-Type: application/json');
echo json_encode($response);
?>
