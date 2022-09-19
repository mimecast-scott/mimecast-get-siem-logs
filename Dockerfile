FROM python
LABEL maintainer="s@mck.la"
RUN apt-get update && apt-get install -y \
&& mkdir -p /mimecast/chk \
&& mkdir /mimecast/logs \
&& pip install requests
WORKDIR /mimecast
COPY . /mimecast

CMD ["python","./get-siem-logs.py"]
