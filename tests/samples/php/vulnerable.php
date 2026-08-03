<?php

$API_KEY = "sk-1234567890abcdef1234567890abcdef";
$DB_PASSWORD = "supersecret123";

function getUser($request) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = '" . $id . "'";
    $result = mysqli_query($conn, $query);
    return $result;
}

function showProfile($request) {
    $user = $_GET['user'];
    echo "<div>Welcome " . $user . "</div>";
}

function pingServer($request) {
    $host = $_GET['host'];
    $output = system("ping -c 1 " . $host);
    return $output;
}

function downloadFile($request) {
    $filename = $_GET['file'];
    $path = "/var/uploads/" . $filename;
    return file_get_contents($path);
}

function loadUserData($data) {
    $user = unserialize($data);
    return $user;
}

function runCode($request) {
    $code = $_GET['code'];
    eval($code);
}

function fetchUrl($request) {
    $url = $_GET['url'];
    $content = file_get_contents($url);
    return $content;
}

function hashPass($password) {
    return md5($password);
}
