<?php

class RefreshTokenGateway
{
    private $conn;
    private $key;

    public function __construct(Database $database, string $key)
    {
        $this->conn = $database->getConnection();
        $this->key = $key;
    }

    public function create(string $token, int $expiry): bool
    {
        $hash = hash_hmac("sha256", $token, $this->key);

        $sql = "INSERT INTO tbl_refresh_token (token_hash, expires_at)
                VALUES (:token_hash, :expires_at)";

        $stmt = $this->conn->prepare($sql);

        $stmt->bindValue(":token_hash", $hash, PDO::PARAM_STR);
        $stmt->bindValue(":expires_at", $expiry, PDO::PARAM_INT);

        return $stmt->execute();
    }

    public function delete(string $token): int
    {
        $hash = hash_hmac("sha256", $token, $this->key);

        $sql = "DELETE FROM tbl_refresh_token
                WHERE token_hash = :token_hash";

        $stmt = $this->conn->prepare($sql);

        $stmt->bindValue(":token_hash", $hash, PDO::PARAM_STR);

        $stmt->execute();

        return $stmt->rowCount();
    }

    public function getByToken($token): array
    {
        $hash = hash_hmac("sha256", $token, $this->key);

        $sql = "SELECT *
                FROM tbl_refresh_token
                WHERE token_hash = :token_hash";

        $stmt = $this->conn->prepare($sql);

        $stmt->bindValue(":token_hash", $hash, PDO::PARAM_STR);

        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function deleteExpired(): int
    {
        $sql = "DELETE FROM tbl_refresh_token
                WHERE expires_at < UNIX_TIMESTAMP()";

        $stmt = $this->conn->query($sql);

        return $stmt->rowCount();
    }
}
