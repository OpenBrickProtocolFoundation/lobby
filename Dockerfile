FROM python:3.12 
WORKDIR /app


# install python dependencies

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt

COPY lobby/ lobby/

## add finalization arguments

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -f -X GET http://localhost:1717/health

EXPOSE 1717

CMD [ "python3", "lobby/main.py", "prod"]
