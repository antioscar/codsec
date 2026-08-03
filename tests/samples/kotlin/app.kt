package com.example

import java.sql.*

fun login(userId: String, password: String): Boolean {
    val conn = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt = conn.createStatement()
    val query = "SELECT * FROM users WHERE id = '" + userId + "'"
    stmt.executeQuery(query)
    val apiKey = "sk-1234567890abcdef1234567890abcdef"
    Runtime.getRuntime().exec("ping " + userId)
    return true
}
