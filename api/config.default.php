<?php

// ======================================
// RENAME THIS TO config.php BEFORE USING
// ======================================
// ======================================
// RENAME THIS TO config.php BEFORE USING
// ======================================
// ======================================
// RENAME THIS TO config.php BEFORE USING
// ======================================
// ======================================
// RENAME THIS TO config.php BEFORE USING
// ======================================
// ======================================
// RENAME THIS TO config.php BEFORE USING
// ======================================

/**
 * @file
 * config.php
 *
 * @brief This file contains all the necessary configuration settings for the
 * application, including database connection details and the secret key
 * for JSON Web Token (JWT) signing.
 *
 * It is designed to be included by other scripts.
 *
 * @return array An associative array containing configuration values.
 */
return [
    'db_server'      => 'localhost',
    'db_username'    => 'username',
    'db_password'    => 'your_very_secret_password',
    'db_name'        => 'the_name_of_the_database',
    'jwt_secret_key' => 'your_jwt_secret_key'
];
?>