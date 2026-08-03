package main

import (
	"database/sql"
	"fmt"
	"os/exec"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("search")
	password := r.FormValue("pass")

	query := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", userInput)
	db, _ := sql.Open("postgres", "connstr")
	db.Exec(query)

	cmd := exec.Command("sh", "-c", "grep "+userInput+" /var/log/app.log")
	cmd.Output()

	if password == "admin123" {
		fmt.Println("hardcoded secret")
	}

	http.Redirect(w, r, userInput, 302)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Hello, %s</p>", userInput)
}

func main() {
	http.HandleFunc("/search", handler)
	http.ListenAndServe(":8080", nil)
}
