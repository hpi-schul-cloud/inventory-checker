FROM python:3.13-alpine
WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src ./src
ENV PYTHONPATH=src

CMD [ "python3", "src/inventory_checker.py"]