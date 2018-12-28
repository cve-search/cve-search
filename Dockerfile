FROM alpine:3.7 as builder
LABEL version="1.0" \
      description="build container"
RUN apk --no-cache add bash python3 g++ gcc libxslt-dev python3-dev  && adduser   -S -D cvesearch
WORKDIR /home/cvesearch/
ADD  . cve_search
RUN chown -R cvesearch cve_search
USER cvesearch
RUN chown -R cvesearch cve_search && \
    cd cve_search && \
    python3 -m venv  virtualenv && \
    source virtualenv/bin/activate && \
    pip3 install -r requirements.txt


FROM alpine:3.7
LABEL version="1.0" \
      description="Search CVE docker image"
EXPOSE 5000
RUN apk --no-cache add  python3  bash  && adduser -u 50 -S -D cvesearch
USER cvesearch
WORKDIR /home/cvesearch/
COPY --chown=50 . cve_search
COPY --from=builder /home/cvesearch/cve_search/virtualenv ./cve_search/virtualenv
VOLUME /home/cvesearch/cve_search/etc /home/cvesearch/cve_search/log /home/cvesearch/cve_search/.ssl
ENTRYPOINT ["/home/cvesearch/cve_search/entrypoint.sh"]
