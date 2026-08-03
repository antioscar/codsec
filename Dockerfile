FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p cache reports

ENTRYPOINT ["python", "main.py"]
CMD ["-p", ".", "--no-llm", "-o", "reports/informe_seguridad.pdf", "-j", "reports/informe_seguridad.json"]
