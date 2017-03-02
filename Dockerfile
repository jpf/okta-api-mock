FROM jfloff/alpine-python:2.7-onbuild

ENV HOST=0.0.0.0

ADD app.py /

EXPOSE 5000

CMD python app.py
