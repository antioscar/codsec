import Foundation

func search(query: String) {
    let sqlQuery = "SELECT * FROM items WHERE name = '" + query + "'"
    let apiKey = "sk-abcdef1234567890abcdef123456"
    let process = Process()
    process.launchPath = "/bin/sh"
    process.arguments = ["-c", "echo " + query]
    process.launch()
    print("<div>" + query + "</div>")
}
