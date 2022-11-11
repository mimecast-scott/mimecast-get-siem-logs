# mimecast-get-siem-logs
A dockerized python container to download Mimecast SIEM logs to disk or pipe via syslog.

This is a modified version of the  python `get-siem-logs.py` script [hosted here](https://integrations.mimecast.com/documentation/tutorials/downloading-siem-logs/). SCHEDULE_DELAY= is the number of seconds between each run of the script. Recommended is `SCHEDULE_DELAY=1800` which is 30 minutes.
https://integrations.mimecast.com/documentation/tutorials/downloading-siem-logs/

You can run this in a docker container using [Docker-Compose.yaml](https://github.com/smck83/mimecast-get-siem-logs/blob/main/docker-compose.yaml)

## Environment Variables
      APP_ID: <-- YOUR MIMECAST APPLICATION ID -->
      APP_KEY: <-- YOUR MIMECAST APPLICATION KEY -->
      EMAIL_ADDRESS: <-- YOUR MIMECAST ACCOUNT E-MAIL ADDRESS : USED TO DETERMINE WHICH CLOUD API ENDPOINT TO CALL -->
      SECRET_KEY: <-- YOUR MIMECAST SECRET KEY -->
      ACCESS_KEY: <-- YOUR MIMECAST ACCESS KEY -->
      SYSLOG_OUTPUT: 'False'
      SYSLOG_SERVER: '127.0.0.1'
      SYSLOG_PORT: '514'
      DELETE_FILES: 'True'
      LOG_FILE_THRESHOLD: '10000'
      SCHEDULE_DELAY: '1800'

## Give it a go
       docker run -it -v /your/mimecast/path/chk:/mimecast/chk \
       -v /your/mimecast/path/logs:/mimecast/logs \
       -e APP_ID='<APP_ID>' \
       -e APP_KEY='<APP_KEY>' \
       -e EMAIL_ADDRESS='<EMAIL_ADDRESS>' \
       -e SECRET_KEY='<SECRET_KEY>' \
       -e ACCESS_KEY='<ACCESS_KEY>' \
       smck83/mimecast-get-siem-logs
  
  ## Mimecast documentation
    To create the required keys in Mimecast, see instructions here: https://community.mimecast.com/s/article/Managing-API-Applications-505230018
