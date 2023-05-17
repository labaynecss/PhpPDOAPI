<?php

class Database
{
    private $conn = null;

    public function __construct(
        $host,
        $name,
        $user,
        $password
    ) {
        $this->host = $host;
        $this->name = $name;
        $this->user = $user;
        $this->password = $password;
    }

    public function getConnection(): PDO
    {
        if ($this->conn === null) {
            $dsn = "mysql:host={$this->host};dbname={$this->name};charset=utf8";

            $this->conn = new PDO($dsn, $this->user, $this->password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
            ]);
        }

        return $this->conn;
    }
}
