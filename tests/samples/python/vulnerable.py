import hashlib
import os
import pickle
import subprocess

API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "admin123"


def login(request):
    user = request.GET.get("user")
    passwd = request.GET.get("pass")
    query = "SELECT * FROM users WHERE user='" + user + "' AND pass='" + passwd + "'"
    cursor.execute(query)
    return cursor.fetchone()


def download_file(request):
    filename = request.GET.get("file")
    path = os.path.join("/var/www/uploads", filename)
    return open(path, "rb").read()


def ping_host(request):
    host = request.GET.get("host")
    result = subprocess.call("ping -c 1 " + host, shell=True)
    return result


def load_session(data):
    try:
        return pickle.loads(data)
    except Exception:
        return {}


def hash_password(passwd):
    return hashlib.md5(passwd.encode()).hexdigest()
