FROM python:3.12 
WORKDIR /app


# install python dependencies

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt

COPY lobby/ lobby/

## add finalization arguments

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -f -X GET http://localhost:1717/health

EXPOSE 3001

CMD [ "python3", "-m" , "flask", "--app=lobby.main", "run", "--host=0.0.0.0", "--port=1717"]
