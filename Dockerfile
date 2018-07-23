FROM python:3.6.5

ENV PYTHONUNBUFFERED=1
RUN pip install flask requests pycrypto
ADD . /blockchain

ENTRYPOINT cd /blockchain && python main.py
